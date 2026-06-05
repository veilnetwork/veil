use std::{
    path::Path,
    process::Child,
    thread,
    time::{Duration, Instant},
};

use super::util::map_node_error;
#[cfg(unix)]
use std::process::{Command, Stdio};

use veil_cfg;
use veil_node_runtime::admin as node;

use super::{
    cli::{DhtCommand, NodeArgs, NodeCommand},
    handlers::{CommandContext, ConfigOps},
    output::{CommandIo, OutputEvent, format_columns},
};

pub fn handle_node_command<I: CommandIo, O: ConfigOps>(
    mut context: CommandContext<'_, I, O>,
    args: NodeArgs,
) -> veil_cfg::Result<()> {
    match args.command {
        NodeCommand::Run {
            foreground,
            daemon_child,
            defer_init,
        } => run_node(&mut context, foreground, daemon_child, defer_init),
        NodeCommand::Stop => request_node_command(&mut context, node::AdminCommand::Stop),
        NodeCommand::Restart => request_node_command(&mut context, node::AdminCommand::Restart),
        NodeCommand::Reload => request_node_command(&mut context, node::AdminCommand::Reload),
        NodeCommand::ApplyConfig { path, persist } => {
            // Read the TOML content от disk or stdin. Use std::io
            // directly — at this point we ара still in the CLI process
            // before connecting к the daemon's admin socket.
            let toml_content = if path.as_os_str() == "-" {
                let mut buf = String::new();
                std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf).map_err(|e| {
                    veil_cfg::ConfigError::ValidationFailed(format!("read stdin: {e}"))
                })?;
                buf
            } else {
                std::fs::read_to_string(&path).map_err(|e| {
                    veil_cfg::ConfigError::ValidationFailed(format!("read {}: {e}", path.display()))
                })?
            };
            request_node_command(
                &mut context,
                node::AdminCommand::ApplyConfig {
                    toml_content,
                    persist,
                },
            )
        }
        NodeCommand::Show => request_node_command(&mut context, node::AdminCommand::Show),
        NodeCommand::Listens => request_node_command(&mut context, node::AdminCommand::Listens),
        NodeCommand::Health => request_node_command(&mut context, node::AdminCommand::Health),
        NodeCommand::Bandwidth => request_node_command(&mut context, node::AdminCommand::Bandwidth),
        NodeCommand::Metrics => request_node_command(&mut context, node::AdminCommand::Metrics),
        NodeCommand::Dht(dht_args) => match dht_args.command {
            DhtCommand::List => request_node_command(&mut context, node::AdminCommand::DhtList),
            DhtCommand::Routing => {
                request_node_command(&mut context, node::AdminCommand::DhtRouting)
            }
            DhtCommand::Get { key } => {
                request_node_command(&mut context, node::AdminCommand::DhtGet { key })
            }
            DhtCommand::RecursiveGet { key, timeout_ms } => request_node_command(
                &mut context,
                node::AdminCommand::DhtRecursiveGet { key, timeout_ms },
            ),
            DhtCommand::Put { key, value } => {
                request_node_command(&mut context, node::AdminCommand::DhtPut { key, value })
            }
            DhtCommand::PublishReplicated {
                key,
                value,
                value_file,
            } => {
                let value_hex = match (value, value_file) {
                    (Some(v), None) => v,
                    (None, Some(p)) => {
                        let bytes = std::fs::read(&p).map_err(|e| {
                            veil_cfg::ConfigError::Io(std::io::Error::new(
                                e.kind(),
                                format!("read --value-file {}: {e}", p.display()),
                            ))
                        })?;
                        veil_util::bytes_to_hex(&bytes)
                    }
                    (Some(_), Some(_)) => {
                        return Err(veil_cfg::ConfigError::ValidationFailed(
                            "node dht publish-replicated: pass exactly one of --value or --value-file"
                                .into(),
                        ));
                    }
                    (None, None) => {
                        return Err(veil_cfg::ConfigError::ValidationFailed(
                            "node dht publish-replicated: --value or --value-file is required"
                                .into(),
                        ));
                    }
                };
                request_node_command(
                    &mut context,
                    node::AdminCommand::DhtPublishReplicated {
                        key,
                        value: value_hex,
                    },
                )
            }
        },
        NodeCommand::DiscoveryList => {
            request_node_command(&mut context, node::AdminCommand::DiscoveryList)
        }
        NodeCommand::GatewayList => {
            request_node_command(&mut context, node::AdminCommand::GatewayList)
        }
        NodeCommand::MeshStatus => {
            request_node_command(&mut context, node::AdminCommand::MeshStatus)
        }
        NodeCommand::BootstrapStatus => {
            request_node_command(&mut context, node::AdminCommand::BootstrapStatus)
        }
        NodeCommand::UpdateStatus => {
            request_node_command(&mut context, node::AdminCommand::UpdateStatus)
        }
        NodeCommand::MobileStatus => {
            request_node_command(&mut context, node::AdminCommand::MobileStatus)
        }
        NodeCommand::Routes { dst_node_id } => request_node_command(
            &mut context,
            node::AdminCommand::Routes {
                dst_filter: dst_node_id,
            },
        ),
        NodeCommand::DiscoverySearch => {
            request_node_command(&mut context, node::AdminCommand::DiscoverySearch)
        }
        NodeCommand::SwapTransport {
            peer_node_id,
            alt_uri,
        } => request_node_command(
            &mut context,
            node::AdminCommand::SwapTransport {
                peer_node_id,
                alt_uri,
            },
        ),
        NodeCommand::ResolveIdentity {
            node_id,
            timeout_ms,
        } => request_node_command(
            &mut context,
            node::AdminCommand::ResolveIdentity {
                node_id,
                timeout_ms,
            },
        ),
        NodeCommand::ResolveName { name, timeout_ms } => request_node_command(
            &mut context,
            node::AdminCommand::ResolveName { name, timeout_ms },
        ),
        NodeCommand::NatProbe {
            target_node_id,
            per_coordinator_timeout_ms,
        } => request_node_command(
            &mut context,
            node::AdminCommand::NatProbe {
                target_node_id,
                per_coordinator_timeout_ms,
            },
        ),
    }
}

fn run_node<I: CommandIo, O: ConfigOps>(
    context: &mut CommandContext<'_, I, O>,
    foreground: bool,
    daemon_child: bool,
    defer_init: bool,
) -> veil_cfg::Result<()> {
    // **--defer-init**: daemon boots с а stub config + ephemeral identity,
    // awaits а runtime `admin apply-config` к provide the real config.
    // Background-spawn mode is unsupported (the child would inherit the
    // stub temp-dir but lose access on parent exit) — caller must use
    // `--foreground` together с `--defer-init`.
    if defer_init {
        if !foreground {
            return Err(veil_cfg::ConfigError::ValidationFailed(
                "--defer-init requires --foreground (background-spawn cannot \
                 survive the temp-stub working dir lifecycle)"
                    .into(),
            ));
        }
        let global = veil_cfg::GlobalConfig::default();
        let runtime = build_runtime(&global)?;
        return runtime
            .block_on(node::run_foreground_deferred())
            .map_err(map_node_error);
    }

    let path = context.config().locate()?;
    let global = veil_cfg::load_config(&path)
        .map(|c| c.global)
        .unwrap_or_default();
    if daemon_child {
        let runtime = build_runtime(&global)?;
        return runtime
            .block_on(node::run_foreground(&path, false))
            .map_err(map_node_error);
    }

    if !foreground {
        spawn_background_node(context, &path)?;
        return Ok(());
    }

    let runtime = build_runtime(&global)?;
    runtime
        .block_on(node::run_foreground(&path, true))
        .map_err(map_node_error)
}

fn spawn_background_node<I: CommandIo, O: ConfigOps>(
    context: &mut CommandContext<'_, I, O>,
    config_path: &Path,
) -> veil_cfg::Result<()> {
    let config = context.config().load(config_path)?;
    let socket = node::admin_socket_path(&config, config_path.parent()).map_err(map_node_error)?;
    let mut child = spawn_background_node_process(
        background_child_executable()?,
        context.config_arg,
        config_path,
    )?;

    wait_for_background_node(&socket, &mut child)?;
    context.io.emit(OutputEvent::message(
        "node started in background".to_owned(),
    ));
    Ok(())
}

fn request_node_command<I: CommandIo, O: ConfigOps>(
    context: &mut CommandContext<'_, I, O>,
    command: node::AdminCommand,
) -> veil_cfg::Result<()> {
    let (config_path, config) = context.config().load_existing()?;
    let socket = node::admin_socket_path(&config, config_path.parent()).map_err(map_node_error)?;
    if !node::admin_anchor_reachable_sync(&socket) {
        return Err(veil_cfg::ConfigError::CommandFailed(format!(
            "admin socket `{}` was not found; start the node with `veil-cli node run`",
            socket.display()
        )));
    }
    let runtime = build_runtime(&veil_cfg::GlobalConfig::default())?;
    let response = runtime
        .block_on(node::send_request(&socket, command))
        .map_err(map_node_error)?;

    if let Some(error) = response.error {
        return Err(veil_cfg::ConfigError::CommandFailed(error));
    }

    match response.result {
        Some(node::AdminResult::Ack { message }) => context.io.emit(OutputEvent::message(message)),
        Some(node::AdminResult::Show(summary)) => {
            context.io.emit(OutputEvent::message(render_show(summary)));
        }
        Some(node::AdminResult::Health(report)) => {
            context.io.emit(OutputEvent::message(render_health(report)));
        }
        Some(node::AdminResult::Bandwidth {
            inbound_limit_kbps,
            outbound_limit_kbps,
            inbound_total_bytes,
            inbound_dropped_bytes,
            outbound_total_bytes,
            outbound_dropped_bytes,
            per_peer_byte_cap_bytes_per_sec,
            per_peer_bytes_allowed_total,
            per_peer_bytes_dropped_total,
        }) => {
            let fmt_limit = |v: i64| {
                if v < 0 {
                    "unlimited".to_owned()
                } else {
                    format!("{v} kbps")
                }
            };
            let fmt_bytes = |b: u64| {
                if b > 1_073_741_824 {
                    format!("{:.2} GiB", b as f64 / 1_073_741_824.0)
                } else if b > 1_048_576 {
                    format!("{:.2} MiB", b as f64 / 1_048_576.0)
                } else if b > 1024 {
                    format!("{:.1} KiB", b as f64 / 1024.0)
                } else {
                    format!("{b} B")
                }
            };
            // b: per-peer byte cap row. Only printed when
            // operator opted в (cap >= 0) so non-mobile deployments
            // don't see noise about a feature they didn't enable.
            // When enabled, drop ratio gives operator decision aid:
            // 0% = "cap well-tuned"; high % = "cap may break legit
            // traffic, consider raising".
            let per_peer_row = if per_peer_byte_cap_bytes_per_sec >= 0 {
                let total = per_peer_bytes_allowed_total + per_peer_bytes_dropped_total;
                let drop_pct = if total == 0 {
                    0.0
                } else {
                    (per_peer_bytes_dropped_total as f64 / total as f64) * 100.0
                };
                format!(
                    "\nper-peer: cap={}/sec passed={} dropped={} ({:.1}%)",
                    fmt_bytes(per_peer_byte_cap_bytes_per_sec as u64),
                    fmt_bytes(per_peer_bytes_allowed_total),
                    fmt_bytes(per_peer_bytes_dropped_total),
                    drop_pct,
                )
            } else {
                String::new()
            };
            context.io.emit(OutputEvent::message(format!(
                "inbound:  limit={} passed={} dropped={}\noutbound: limit={} passed={} dropped={}{per_peer_row}",
                fmt_limit(inbound_limit_kbps), fmt_bytes(inbound_total_bytes), fmt_bytes(inbound_dropped_bytes),
                fmt_limit(outbound_limit_kbps), fmt_bytes(outbound_total_bytes), fmt_bytes(outbound_dropped_bytes),
            )));
        }
        Some(node::AdminResult::Listens { listens }) => {
            context
                .io
                .emit(OutputEvent::message(render_listens(&listens)));
        }
        Some(node::AdminResult::Metrics(snap)) => {
            context.io.emit(OutputEvent::message(render_metrics(&snap)));
        }
        Some(node::AdminResult::DhtEntries { entries, truncated }) => {
            context.io.emit(OutputEvent::message(render_dht_entries(
                &entries, truncated,
            )));
        }
        Some(node::AdminResult::DhtContacts { contacts }) => {
            context
                .io
                .emit(OutputEvent::message(render_dht_contacts(&contacts)));
        }
        Some(node::AdminResult::DhtValue {
            key,
            value_hex,
            value_len,
        }) => {
            context.io.emit(OutputEvent::message(render_dht_value(
                &key,
                value_hex.as_deref(),
                value_len,
            )));
        }
        Some(node::AdminResult::ResolvedIdentity {
            node_id,
            master_algo,
            active_key_idx,
            active_device_id,
        }) => {
            context.io.emit(OutputEvent::message(format!(
                "resolved + verified\nnode_id: {node_id}\nmaster_algo: {master_algo}\nactive_key_idx: {active_key_idx}\nactive_device_id: {active_device_id}",
            )));
        }
        Some(node::AdminResult::NatProbeResult {
            responder_node_id,
            candidate_count,
            candidates,
        }) => {
            let mut out = format!(
                "NAT probe succeeded\nresponder: {responder_node_id}\ncandidates ({candidate_count}):",
            );
            for c in &candidates {
                let kind = match c.candidate_type {
                    0 => "host",
                    1 => "srflx",
                    2 => "relay",
                    _ => "?",
                };
                out.push_str(&format!(
                    "\n  - {kind} (atyp={}) {} priority={}",
                    c.atyp, c.addr, c.priority,
                ));
            }
            context.io.emit(OutputEvent::message(out));
        }
        Some(node::AdminResult::DiscoveryEntries { attachments }) => {
            context
                .io
                .emit(OutputEvent::message(render_discovery_entries(&attachments)));
        }
        Some(node::AdminResult::GatewayAttachments { nodes }) => {
            context
                .io
                .emit(OutputEvent::message(render_gateway_nodes(&nodes)));
        }
        Some(node::AdminResult::MeshStatus { gateways }) => {
            context
                .io
                .emit(OutputEvent::message(render_mesh_status(&gateways)));
        }
        Some(node::AdminResult::BootstrapStatus(status)) => {
            context
                .io
                .emit(OutputEvent::message(render_bootstrap_status(&status)));
        }
        Some(node::AdminResult::UpdateStatus(status)) => {
            context
                .io
                .emit(OutputEvent::message(render_update_status(&status)));
        }
        Some(node::AdminResult::MobileStatus(status)) => {
            context
                .io
                .emit(OutputEvent::message(render_mobile_status(&status)));
        }
        Some(node::AdminResult::Routes { routes, multi_path }) => {
            context
                .io
                .emit(OutputEvent::message(render_routes(&routes, &multi_path)));
        }
        Some(node::AdminResult::DiscoverySearchTriggered) => {
            context.io.emit(OutputEvent::message(
                "route discovery search triggered".to_owned(),
            ));
        }
        Some(_) | None => context
            .io
            .emit(OutputEvent::message("node command completed".to_owned())),
    }

    Ok(())
}

fn render_health(report: node::AdminHealthReport) -> String {
    format!(
        "status: {}\ntick: {}\nsessions: {}",
        report.status, report.tick, report.sessions,
    )
}

fn render_show(summary: node::AdminNodeSummary) -> String {
    let features = if summary.build_features.is_empty() {
        "(none)".to_owned()
    } else {
        summary.build_features.join(", ")
    };
    format!(
        "node_id: {}\nrole: {}\nversion: {}\nbuild_features: {}\nconfig_path: {}\nadmin_socket: {}\nforeground: {}\nuptime_secs: {}\nmetrics_active: {}\nmetrics_endpoint: {}\npeers_configured: {}\nsessions_active: {}\nlistens_active: {}",
        summary.node_id,
        summary.role,
        summary.version,
        features,
        summary.config_path,
        summary.admin_socket,
        summary.foreground_mode,
        summary.uptime_secs,
        summary.metrics_active,
        summary.metrics_endpoint.as_deref().unwrap_or("-"),
        summary.peers_configured,
        summary.sessions_active,
        summary.listens_active,
    )
}

fn render_listens(listens: &[node::AdminListenEntry]) -> String {
    let mut lines = vec![format_columns(
        &[
            "listen_id",
            "listener_handle",
            "active",
            "local_addr",
            "transport",
        ],
        &[10, 18, 6, 21, 0],
    )];
    for listen in listens {
        lines.push(format_columns(
            &[
                listen.listen_id.as_str(),
                listen.listener_handle.as_deref().unwrap_or("-"),
                if listen.active { "true" } else { "false" },
                listen.local_addr.as_deref().unwrap_or("-"),
                listen.transport.as_str(),
            ],
            &[10, 18, 6, 21, 0],
        ));
    }
    lines.join("\n")
}

fn render_metrics(snap: &node::AdminMetricsSnapshot) -> String {
    // when metrics are disabled every counter below is
    // unconditionally zero — emitting 35 zero lines just buries the
    // actionable hint. Print only the header in that case.
    if !snap.metrics_enabled {
        return "metrics: DISABLED — add [metrics] section to config to enable Prometheus exporter"
            .to_owned();
    }
    let header = "metrics: enabled".to_owned();
    format!(
        "{header}\n\
         \n\
         configured_peers:                    {}\n\
         active_sessions:                     {}\n\
         inbound_sessions_total:              {}\n\
         outbound_connect_attempts_total:     {}\n\
         outbound_connect_failures_total:     {}\n\
         transport_bytes_rx_total:            {}\n\
         transport_bytes_tx_total:            {}\n\
         session_handshake_failures_total:    {}\n\
         dht_store_total:                     {}\n\
         dht_lookup_total:                    {}\n\
         mesh_relay_hops_total:               {}\n\
         decrypt_failures_total:              {}\n\
         storage_evictions_total:             {}\n\
         route_miss_total:                    {}\n\
         discovery_triggered_total:           {}\n\
         route_recovery_total:                {}\n\
         network_reachability_score_pct:      {}\n\
         route_selection_avg_rtt_ms:          {}\n\
         vivaldi_prediction_error_ms:         {}\n\
         vivaldi_coord_x:                     {}\n\
         vivaldi_coord_y:                     {}\n\
         vivaldi_coord_height:                {}\n\
         vivaldi_coord_error:                 {}\n\
         rate_limit_drops_total:              {}\n\
         backpressure_received_total:         {}\n\
         ban_actions_total:                   {}\n\
         rt_frames_rx_total:                  {}\n\
         rt_frames_tx_total:                  {}\n\
         rt_seq_gaps_total:                   {}\n\
         app_msg_channel_full_total:          {}\n\
         app_msg_channel_closed_total:        {}\n\
         mlkem_key_age_secs:                  {}",
        snap.configured_peers,
        snap.active_sessions,
        snap.inbound_sessions_total,
        snap.outbound_connect_attempts_total,
        snap.outbound_connect_failures_total,
        snap.transport_bytes_rx_total,
        snap.transport_bytes_tx_total,
        snap.session_handshake_failures_total,
        snap.dht_store_total,
        snap.dht_lookup_total,
        snap.mesh_relay_hops_total,
        snap.decrypt_failures_total,
        snap.storage_evictions_total,
        snap.route_miss_total,
        snap.discovery_triggered_total,
        snap.route_recovery_total,
        snap.network_reachability_score_pct,
        snap.route_selection_avg_rtt_ms,
        snap.vivaldi_prediction_error_ms,
        snap.vivaldi_coord_x,
        snap.vivaldi_coord_y,
        snap.vivaldi_coord_height,
        snap.vivaldi_coord_error,
        snap.rate_limit_drops_total,
        snap.backpressure_received_total,
        snap.ban_actions_total,
        snap.rt_frames_rx_total,
        snap.rt_frames_tx_total,
        snap.rt_seq_gaps_total,
        snap.app_msg_channel_full_total,
        snap.app_msg_channel_closed_total,
        snap.mlkem_key_age_secs,
    )
}

fn render_dht_entries(entries: &[node::AdminDhtEntry], truncated: bool) -> String {
    if entries.is_empty() {
        return "no DHT entries".to_owned();
    }
    let mut lines = vec![format_columns(&["key", "len", "value"], &[66, 6, 0])];
    for e in entries {
        lines.push(format_columns(
            &[
                e.key.as_str(),
                &e.value_len.to_string(),
                e.value_hex.as_str(),
            ],
            &[66, 6, 0],
        ));
    }
    if truncated {
        lines.push(format!(
            "… list truncated at {} entries (store has more)",
            entries.len()
        ));
    }
    lines.join("\n")
}

fn render_dht_contacts(contacts: &[node::AdminDhtContact]) -> String {
    if contacts.is_empty() {
        return "routing table is empty".to_owned();
    }
    let mut lines = vec![format_columns(&["node_id", "transport"], &[66, 0])];
    for c in contacts {
        lines.push(format_columns(
            &[c.node_id.as_str(), c.transport.as_str()],
            &[66, 0],
        ));
    }
    lines.join("\n")
}

fn render_dht_value(key: &str, value_hex: Option<&str>, value_len: usize) -> String {
    match value_hex {
        Some(v) => format!("key:   {key}\nlen:   {value_len}\nvalue: {v}"),
        None => format!("key:   {key}\nnot found"),
    }
}

fn render_discovery_entries(attachments: &[node::AdminAttachmentEntry]) -> String {
    if attachments.is_empty() {
        return "no discovery entries".to_owned();
    }
    let mut lines = vec![format_columns(
        &["node_id", "role", "epoch", "expires_at", "gateways"],
        &[66, 4, 8, 12, 0],
    )];
    for a in attachments {
        let gateways = if a.gateways.is_empty() {
            "-".to_owned()
        } else {
            a.gateways.join(",")
        };
        lines.push(format_columns(
            &[
                a.node_id.as_str(),
                &a.role.to_string(),
                &a.epoch.to_string(),
                &a.expires_at.to_string(),
                &gateways,
            ],
            &[66, 4, 8, 12, 0],
        ));
    }
    lines.join("\n")
}

fn render_gateway_nodes(nodes: &[String]) -> String {
    if nodes.is_empty() {
        return "no attached nodes".to_owned();
    }
    nodes.join("\n")
}

/// render the leaf-side mesh status table. Best-first
/// ordering by composite latency+battery score is preserved from the
/// runtime snapshot. Battery shows `AC` for the 0 sentinel ("AC
/// power / unknown") so operators don't think a wall-powered Pi is
/// "0 % charged". RTT shows `?` until the first probe records a
/// sample.
fn render_mesh_status(gateways: &[node::AdminMeshGatewayEntry]) -> String {
    if gateways.is_empty() {
        return "no auto-discovered gateways yet \
                (waiting for mesh beacons; check `[mesh]` config + \
                that this network has a gateway running)"
            .to_owned();
    }
    let mut lines = Vec::with_capacity(gateways.len() + 2);
    lines.push(
        "STATUS  RTT     BAT   AGE  EXPIRES  ADDR                                 NODE_ID"
            .to_owned(),
    );
    for gw in gateways {
        let status = if gw.is_active { "ACTIVE" } else { "stdby " };
        let rtt = match gw.rtt_smoothed_ms {
            Some(ms) => format!("{:>5}ms", ms),
            None => "    ?  ".to_owned(),
        };
        let battery = if gw.battery_level == 0 {
            "  AC".to_owned()
        } else {
            format!("{:>3}%", gw.battery_level)
        };
        // Truncate node_id to first 16 hex chars for readability —
        // operators who need the full id can run `node show` or pipe
        // through json output.
        let short_id = if gw.node_id.len() > 16 {
            &gw.node_id[..16]
        } else {
            &gw.node_id
        };
        lines.push(format!(
            "{}  {}  {}  {:>3}s {:>6}s  {:<35}  {}…",
            status, rtt, battery, gw.last_seen_secs_ago, gw.expires_in_secs, gw.veil_addr, short_id,
        ));
    }
    lines.join("\n")
}

/// render a duration like "2d", "3h", "5m", "12s" — the
/// shortest unit that still carries useful precision for the
/// freshness diag. The operator just needs "is it fresh or stale";
/// they can `node bootstrap-status --json` for exact seconds.
fn fmt_age(secs: u64) -> String {
    if secs >= 86400 {
        format!("{}d", secs / 86400)
    } else if secs >= 3600 {
        format!("{}h", secs / 3600)
    } else if secs >= 60 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

/// render the bootstrap-chain status as one labelled row
/// per defense layer + a verdict line that translates `healthy_layers`
/// into an operator-facing recommendation. ALWAYS prints every row
/// even when a layer is empty — the empty row IS the diagnostic
/// signal we want to surface.
fn render_bootstrap_status(s: &node::AdminBootstrapStatus) -> String {
    let freshness = match (
        s.discovered_cache.freshest_secs_ago,
        s.discovered_cache.oldest_secs_ago,
    ) {
        (Some(fresh), Some(old)) => {
            format!(", freshest {}, oldest {}", fmt_age(fresh), fmt_age(old))
        }
        _ => String::new(),
    };
    let cache_row = if s.discovered_cache.persistent {
        format!(
            "{} entries (persistent: {}){freshness}",
            s.discovered_cache.entries,
            s.discovered_cache.path.as_deref().unwrap_or("?"),
        )
    } else {
        format!(
            "{} entries (in-memory only — set `global.discovered_peers_cache_path` to persist){freshness}",
            s.discovered_cache.entries,
        )
    };
    let https_row = if s.https_urls > 0 {
        format!(
            "{} URL(s) configured  (curl -v <url> to verify each one returns JSON 200)",
            s.https_urls,
        )
    } else {
        "not configured".to_owned()
    };
    let dns_row = match &s.dns_domain {
        Some(d) => format!("configured: {d}  (run `dig TXT _veil._bootstrap.{d}` to verify)"),
        None => "not configured".to_owned(),
    };
    // P1: structurally exhaustive — `usize` can only be
    // 0, 1, or ≥2. Drop the guard so the compiler proves exhaustiveness
    // and the `unreachable!` panic-trap goes away.
    let verdict = match s.healthy_layers {
        0 => "VERDICT  no bootstrap source available — node will not connect.\n\
              Add `[[bootstrap_peers]]`, set `bootstrap_dns_domain`, configure \
              `bootstrap_https_urls`, or accept an invite."
            .to_owned(),
        1 => "VERDICT  single bootstrap layer — at risk if a censor takes it down.\n\
              Add at least one more source for layered defense."
            .to_owned(),
        n => format!(
            "VERDICT  {n}/{} layers healthy — bootstrap is resilient to single-source takedown.",
            s.total_layers,
        ),
    };
    format!(
        "BOOTSTRAP CHAIN STATUS\n\
         \n\
         L1 operator-curated peers : {} entries\n\
         L2 builtin compile-time   : {} entries\n\
         L3 HTTPS bootstrap URLs   : {}\n\
         L4 DNS bootstrap domain   : {}\n\
         L5 discovered-peer cache  : {}\n\
         \n\
         {verdict}",
        s.config_peers, s.builtin_seeds, https_row, dns_row, cache_row,
    )
}

/// render the update-mechanism status snapshot. Like
/// bootstrap-status, prints all rows even when feature is disabled
/// — empty/None rows are themselves the diagnostic signal ("you
/// haven't configured update mechanism yet").
fn render_update_status(s: &node::AdminUpdateStatus) -> String {
    let check_row = if s.check_configured {
        format!("CONFIGURED — {} URL(s)", s.manifest_url_count)
    } else {
        "not configured (set `update.manifest_urls` + `update.expected_issuer_pk` in config)"
            .to_owned()
    };
    let apply_row = if s.apply_configured {
        "CONFIGURED — operator can run `veil-cli update apply`".to_owned()
    } else if s.check_configured {
        "not configured (also set `update.install_path` + `update.installed_version_path` to enable apply)".to_owned()
    } else {
        "not configured (depends on check being configured first)".to_owned()
    };
    let interval_row = match s.check_interval_secs {
        Some(secs) => {
            // Operator-friendly hours/minutes formatting for the
            // common cellular/desktop cadences (24h / 6h / 1h)
            // without pulling in chrono.
            if secs >= 3600 && secs % 3600 == 0 {
                format!("auto-poll every {} h ({secs} s)", secs / 3600)
            } else if secs >= 60 && secs % 60 == 0 {
                format!("auto-poll every {} min ({secs} s)", secs / 60)
            } else {
                format!("auto-poll every {secs} s")
            }
        }
        None => "auto-poll DISABLED (manual `update check` only)".to_owned(),
    };
    let installed_row = match s.installed_release_unix {
        Some(unix) => format!("release_unix = {unix}"),
        None => {
            "not recorded (fresh install OR `installed_version_path` not configured)".to_owned()
        }
    };
    let bg_row = if s.mobile_background_mode {
        "ACTIVE — keepalive intervals stretched, sessions preserved through OS suspension"
    } else {
        "inactive (foreground cadence)"
    };
    format!(
        "UPDATE MECHANISM STATUS\n\
         \n\
         check path     : {check_row}\n\
         apply path     : {apply_row}\n\
         poll cadence   : {interval_row}\n\
         installed      : {installed_row}\n\
         mobile bg mode : {bg_row}\n",
    )
}

/// render mobile-mode runtime state. Surfaces
/// both config knobs AND resolved values so operator answers
/// "why is my keepalive 30 min when I expected 30s?" in one read.
fn render_mobile_status(s: &node::AdminMobileStatus) -> String {
    let bg_state = if s.background_mode {
        "ACTIVE"
    } else {
        "inactive"
    };
    let bg_implication = if s.background_mode {
        format!(
            " — keepalive intervals stretched by {}× (foreground would be 1×)",
            s.background_keepalive_factor
        )
    } else {
        " — foreground cadence (no keepalive scaling)".to_owned()
    };
    let battery_implication = if s.battery_level_pct == 100 {
        // Sentinel for "AC / unknown / non-Linux".
        " (AC / unknown — never throttled on this signal)".to_owned()
    } else if let Some(threshold) = s.low_battery_threshold_pct {
        if s.battery_level_pct <= threshold {
            format!(
                " — below threshold {threshold}%; route-probes stretched {}×",
                s.battery_route_probe_factor
            )
        } else {
            format!(" — above threshold {threshold}%; route-probes at full cadence")
        }
    } else {
        " — battery awareness DISABLED in config".to_owned()
    };
    format!(
        "MOBILE-MODE STATUS\n\
         \n\
         background mode    : {bg_state}{bg_implication}\n\
         background config  : multiplier={mult}× (clamped at MAX=120; effective factor={factor})\n\
         battery level      : {pct}%{battery_implication}\n\
         battery config     : threshold={threshold}, multiplier={battery_mult}× (clamped at MAX=16)\n",
        bg_state = bg_state,
        bg_implication = bg_implication,
        mult = s.background_keepalive_multiplier,
        factor = s.background_keepalive_factor,
        pct = s.battery_level_pct,
        battery_implication = battery_implication,
        threshold = s
            .low_battery_threshold_pct
            .map(|t| format!("{t}%"))
            .unwrap_or_else(|| "DISABLED".to_owned()),
        battery_mult = s.low_battery_multiplier,
    )
}

fn render_routes(
    routes: &[node::AdminRouteEntry],
    multi_path: &node::AdminMultiPathConfig,
) -> String {
    let mut lines = Vec::new();

    // header line with multi-path settings — operator sees at a
    // glance whether the alt routes printed below are actually being used
    // for delivery (multi-path / redundant-send) or are just dormant
    // failover candidates.
    let mp_status = if multi_path.multi_path_enabled {
        format!(
            "multi-path: ON (paths={}, prio≤{})",
            multi_path.max_parallel_paths, multi_path.multi_path_min_priority,
        )
    } else {
        "multi-path: off".to_owned()
    };
    let redund_status = if multi_path.redundant_send {
        "redundant-send: ON"
    } else {
        "redundant-send: off"
    };
    lines.push(format!(
        "[routing config] {mp_status}  |  {redund_status}  |  ecmp_band={:.2}",
        multi_path.ecmp_score_band,
    ));
    lines.push(String::new());

    if routes.is_empty() {
        lines.push("route cache is empty".to_owned());
        return lines.join("\n");
    }
    // Group by dst, print best (first) hop inline, secondary hops indented.
    use std::collections::BTreeMap;
    let mut by_dst: BTreeMap<&str, Vec<&node::AdminRouteEntry>> = BTreeMap::new();
    for r in routes {
        by_dst.entry(r.dst.as_str()).or_default().push(r);
    }
    for bucket in by_dst.values_mut() {
        bucket.sort_by_key(|r| r.score);
    }

    for (dst, hops) in &by_dst {
        let best = hops[0];
        lines.push(format!(
            "{}  →  {}  score={}  hops={}",
            dst, best.next_hop, best.score, best.hops,
        ));
        for alt in &hops[1..] {
            lines.push(format!(
                "{}     {}  score={}  hops={}  (alt)",
                " ".repeat(dst.len()),
                alt.next_hop,
                alt.score,
                alt.hops,
            ));
        }
    }
    lines.join("\n")
}

fn build_runtime(global: &veil_cfg::GlobalConfig) -> veil_cfg::Result<tokio::runtime::Runtime> {
    veil_cfg::build_tokio_runtime(&global.runtime_config()).map_err(veil_cfg::ConfigError::Io)
}

fn background_child_executable() -> veil_cfg::Result<std::path::PathBuf> {
    if let Some(path) = std::env::var_os("VEIL_CLI_EXECUTABLE") {
        return Ok(path.into());
    }
    std::env::current_exe().map_err(veil_cfg::ConfigError::Io)
}

fn spawn_background_node_process(
    executable: std::path::PathBuf,
    config_arg: Option<&Path>,
    config_path: &Path,
) -> veil_cfg::Result<Child> {
    #[cfg(not(unix))]
    {
        let _ = executable;
        let _ = config_arg;
        let _ = config_path;
        Err(veil_cfg::ConfigError::ValidationFailed(
            "background node run is only supported on unix-like systems".to_owned(),
        ))
    }

    #[cfg(unix)]
    {
        let mut command = Command::new(executable);
        command.stdin(Stdio::null()).stdout(Stdio::null());
        if let Some(config_arg) = config_arg {
            command.arg("--config").arg(config_arg);
        } else {
            command.arg("--config").arg(config_path);
        }
        command
            .arg("node")
            .arg("run")
            .arg("--foreground")
            .arg("--daemon-child");
        // scrub env to allow-list before spawn.
        // Same rationale as admin::spawn_restart_child — daemon-mode
        // children inherit parent env wholesale otherwise, which lets
        // `LD_PRELOAD`, etc. live across the daemon transition.
        veil_util::scrub_command_env(&mut command);
        veil_util::setsid_on_spawn(&mut command);
        command.spawn().map_err(veil_cfg::ConfigError::Io)
    }
}

fn wait_for_background_node(socket: &Path, child: &mut Child) -> veil_cfg::Result<()> {
    let runtime = build_runtime(&veil_cfg::GlobalConfig::default())?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().map_err(veil_cfg::ConfigError::Io)? {
            return Err(veil_cfg::ConfigError::ValidationFailed(format!(
                "background node exited before admin socket became ready: {status}"
            )));
        }

        match runtime.block_on(node::send_request(socket, node::AdminCommand::Show)) {
            Ok(response) if response.error.is_none() => return Ok(()),
            Ok(_) | Err(_) => {}
        }

        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(veil_cfg::ConfigError::ValidationFailed(
                "background node did not become ready before timeout".to_owned(),
            ));
        }

        thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        process::Command,
    };

    use super::*;
    use crate::cmd::test_support::{BufferIo, MockConfigOps};
    use crate::test_support;
    use veil_cfg::{
        Config, GlobalConfig, IdentityConfig, ListenConfig, ListenId, LogsConfig, NodeId,
        PeerConfig, PeerId,
    };

    // ── bootstrap-status renderer ─────────────────────────

    fn sample_bootstrap_status(
        config_peers: usize,
        builtin: usize,
        https_urls: usize,
        dns: Option<&str>,
        cache_entries: usize,
        cache_persistent: bool,
    ) -> node::AdminBootstrapStatus {
        let healthy = (config_peers > 0) as u8
            + (builtin > 0) as u8
            + (https_urls > 0) as u8
            + dns.is_some() as u8
            + (cache_entries > 0) as u8;
        node::AdminBootstrapStatus {
            config_peers,
            builtin_seeds: builtin,
            https_urls,
            dns_domain: dns.map(str::to_owned),
            discovered_cache: node::AdminDiscoveredCacheStatus {
                persistent: cache_persistent,
                path: cache_persistent.then(|| "/var/lib/veil/cache.json".to_owned()),
                entries: cache_entries,
                freshest_secs_ago: None,
                oldest_secs_ago: None,
            },
            healthy_layers: healthy,
            total_layers: 5,
        }
    }

    fn sample_bootstrap_status_with_freshness(
        cache_entries: usize,
        cache_persistent: bool,
        freshest_secs_ago: u64,
        oldest_secs_ago: u64,
    ) -> node::AdminBootstrapStatus {
        let mut s = sample_bootstrap_status(0, 0, 0, None, cache_entries, cache_persistent);
        s.discovered_cache.freshest_secs_ago = Some(freshest_secs_ago);
        s.discovered_cache.oldest_secs_ago = Some(oldest_secs_ago);
        s
    }

    /// fmt_age picks shortest unit with useful precision.
    #[test]
    fn epic484_4_fmt_age_picks_shortest_useful_unit() {
        assert_eq!(fmt_age(0), "0s");
        assert_eq!(fmt_age(45), "45s");
        assert_eq!(fmt_age(60), "1m");
        assert_eq!(fmt_age(3599), "59m");
        assert_eq!(fmt_age(3600), "1h");
        assert_eq!(fmt_age(86399), "23h");
        assert_eq!(fmt_age(86400), "1d");
        assert_eq!(fmt_age(45 * 86400), "45d");
    }

    /// cache row shows freshness window when present.
    #[test]
    fn epic484_4_cache_row_renders_freshness_window() {
        // Freshest entry 2 days ago, oldest 45 days ago — a real
        // mid-life cache state that says "still useful but starting
        // to age out".
        let r = render_bootstrap_status(&sample_bootstrap_status_with_freshness(
            8,
            true,
            2 * 86400,
            45 * 86400,
        ));
        let l5 = r
            .lines()
            .find(|l| l.contains("L5"))
            .unwrap_or_else(|| panic!("L5 row missing: {r}"));
        assert!(
            l5.contains("freshest 2d"),
            "L5 must surface freshest age: {l5}"
        );
        assert!(
            l5.contains("oldest 45d"),
            "L5 must surface oldest age: {l5}"
        );
    }

    /// cache row OMITS freshness window when cache is empty.
    /// Empty cache = no entries to derive timestamps from; suppressing
    /// the parenthetical keeps the row terse and unambiguous.
    #[test]
    fn epic484_4_empty_cache_row_omits_freshness_window() {
        let r = render_bootstrap_status(&sample_bootstrap_status(0, 0, 0, None, 0, false));
        let l5 = r
            .lines()
            .find(|l| l.contains("L5"))
            .unwrap_or_else(|| panic!("L5 row missing: {r}"));
        assert!(
            !l5.contains("freshest"),
            "empty cache must not render freshest age: {l5}"
        );
        assert!(
            !l5.contains("oldest"),
            "empty cache must not render oldest age: {l5}"
        );
    }

    #[test]
    fn epic484_4_bootstrap_status_zero_layers_warns_will_not_connect() {
        let r = render_bootstrap_status(&sample_bootstrap_status(0, 0, 0, None, 0, false));
        assert!(r.contains("VERDICT"), "verdict line missing: {r}");
        assert!(
            r.contains("will not connect"),
            "0-layer verdict should warn about no connectivity: {r}"
        );
        // Should still print all 5 layer rows.
        for label in ["L1", "L2", "L3", "L4", "L5"] {
            assert!(
                r.contains(label),
                "all 5 layer labels must be present, missing {label}: {r}"
            );
        }
    }

    #[test]
    fn epic484_4_bootstrap_status_single_layer_warns_about_censorship_risk() {
        let r = render_bootstrap_status(&sample_bootstrap_status(3, 0, 0, None, 0, false));
        assert!(
            r.contains("single bootstrap layer"),
            "1-layer verdict should warn about single source: {r}"
        );
        assert!(r.contains("3 entries"), "config_peers count missing: {r}");
    }

    #[test]
    fn epic484_4_bootstrap_status_multi_layer_reports_resilient() {
        let r = render_bootstrap_status(&sample_bootstrap_status(
            2,
            5,
            1,
            Some("veil.example"),
            8,
            true,
        ));
        assert!(
            r.contains("5/5 layers healthy"),
            "all 5 layers should report healthy: {r}"
        );
        assert!(
            r.contains("resilient"),
            "verdict should mention resilience: {r}"
        );
        assert!(r.contains("veil.example"), "DNS domain not rendered: {r}");
        assert!(
            r.contains("/var/lib/veil/cache.json"),
            "cache path missing for persistent variant: {r}"
        );
        // Sanity: dig-hint included for DNS row.
        assert!(r.contains("dig TXT"), "operator should see dig hint: {r}");
    }

    #[test]
    fn epic484_4_bootstrap_status_in_memory_cache_hints_at_persist_path() {
        let r = render_bootstrap_status(&sample_bootstrap_status(0, 0, 0, None, 1, false));
        assert!(
            r.contains("in-memory only"),
            "non-persistent cache should be flagged: {r}"
        );
        assert!(
            r.contains("discovered_peers_cache_path"),
            "should hint at the config knob to enable persistence: {r}"
        );
    }

    /// HTTPS row surfaces URL count + curl hint when configured.
    #[test]
    fn epic481_4_bootstrap_status_https_row_renders_count_and_hint() {
        let r = render_bootstrap_status(&sample_bootstrap_status(0, 0, 3, None, 0, false));
        assert!(
            r.contains("L3 HTTPS bootstrap URLs"),
            "L3 label must be HTTPS: {r}"
        );
        assert!(
            r.contains("3 URL(s) configured"),
            "should report HTTPS URL count: {r}"
        );
        assert!(
            r.contains("curl -v"),
            "should include verification hint: {r}"
        );
    }

    /// zero-URL HTTPS row says "not configured", not blank.
    #[test]
    fn epic481_4_bootstrap_status_zero_https_says_not_configured() {
        let r = render_bootstrap_status(&sample_bootstrap_status(1, 0, 0, None, 0, false));
        // Find the L3 line and ensure it says "not configured".
        let l3 = r
            .lines()
            .find(|l| l.contains("L3 HTTPS"))
            .unwrap_or_else(|| panic!("L3 row missing: {r}"));
        assert!(
            l3.contains("not configured"),
            "L3 with 0 URLs must say `not configured`: {l3}"
        );
    }

    // ── update-status renderer ────────────────────────────────

    fn sample_update_status(
        check_configured: bool,
        apply_configured: bool,
        manifest_url_count: usize,
        check_interval_secs: Option<u64>,
        installed_release_unix: Option<u64>,
        mobile_background_mode: bool,
    ) -> node::AdminUpdateStatus {
        node::AdminUpdateStatus {
            check_configured,
            apply_configured,
            manifest_url_count,
            check_interval_secs,
            installed_release_unix,
            mobile_background_mode,
        }
    }

    #[test]
    fn epic484_5_update_status_default_says_not_configured() {
        // Brand-new node with no [update] section: status must
        // surface "not configured" + actionable config hint, NOT
        // a misleading "ok" blank line that operators could
        // mistake for "all good".
        let r = render_update_status(&sample_update_status(false, false, 0, None, None, false));
        assert!(
            r.contains("not configured"),
            "default status must surface 'not configured': {r}"
        );
        assert!(
            r.contains("update.manifest_urls"),
            "must hint at the config field name: {r}"
        );
        assert!(
            r.contains("update.expected_issuer_pk"),
            "must hint at issuer pk field too: {r}"
        );
    }

    #[test]
    fn epic484_5_update_status_check_only_says_configure_apply_too() {
        // Operator wired check but not install_path / state_path
        // — status must guide them to enable apply also (NOT
        // silently say "all set" when the apply path won't work).
        let r = render_update_status(&sample_update_status(
            true,
            false,
            3,
            Some(21600),
            None,
            false,
        ));
        let apply_line = r
            .lines()
            .find(|l| l.contains("apply path"))
            .unwrap_or_else(|| panic!("apply path row missing: {r}"));
        assert!(
            apply_line.contains("install_path"),
            "apply row must guide operator to install_path field: {apply_line}"
        );
        assert!(
            apply_line.contains("installed_version_path"),
            "apply row must guide to installed_version_path too: {apply_line}"
        );
    }

    #[test]
    fn epic484_5_update_status_full_config_renders_url_count_and_interval() {
        let r = render_update_status(&sample_update_status(
            true,
            true,
            4,
            Some(86_400),
            Some(1_704_067_200),
            false,
        ));
        assert!(
            r.contains("CONFIGURED — 4 URL(s)"),
            "must show URL count: {r}"
        );
        assert!(
            r.contains("CONFIGURED — operator can run"),
            "apply row must indicate operator can run apply: {r}"
        );
        assert!(
            r.contains("auto-poll every 24 h"),
            "must format 86_400s as '24 h': {r}"
        );
        assert!(
            r.contains("release_unix = 1704067200"),
            "must show installed release_unix: {r}"
        );
    }

    #[test]
    fn epic484_5_update_status_disabled_auto_poll_says_manual_only() {
        // Operator opted into check but didn't set check_interval_secs
        // (manual-check-only deployment). Status must NOT show a
        // misleading "polling every 0 s" — must explicitly say
        // auto-poll DISABLED + how to use manual check.
        let r = render_update_status(&sample_update_status(
            true,
            true,
            1,
            None,
            Some(1_700_000_000),
            false,
        ));
        assert!(
            r.contains("auto-poll DISABLED"),
            "None interval must say auto-poll DISABLED: {r}"
        );
        assert!(
            r.contains("manual"),
            "must mention manual check option: {r}"
        );
    }

    #[test]
    fn epic484_5_update_status_fresh_install_says_not_recorded() {
        // installed_release_unix is None either because state file
        // is missing (fresh install) OR installed_version_path
        // wasn't configured. Status must surface this distinction
        // so operator can investigate (NOT silently default to
        // "release_unix = 0" which would be misleading).
        let r = render_update_status(&sample_update_status(
            true,
            false,
            1,
            Some(86_400),
            None,
            false,
        ));
        assert!(
            r.contains("not recorded"),
            "missing installed_release_unix must surface as 'not recorded': {r}"
        );
        assert!(
            r.contains("fresh install"),
            "must hint at fresh-install scenario: {r}"
        );
    }

    // ── mobile-status renderer ────────────────────────

    fn sample_mobile_status(
        background_mode: bool,
        background_keepalive_multiplier: u32,
        background_keepalive_factor: u32,
        battery_level_pct: u8,
        low_battery_threshold_pct: Option<u8>,
        low_battery_multiplier: u32,
        battery_route_probe_factor: u32,
    ) -> node::AdminMobileStatus {
        node::AdminMobileStatus {
            background_mode,
            background_keepalive_multiplier,
            background_keepalive_factor,
            battery_level_pct,
            low_battery_threshold_pct,
            low_battery_multiplier,
            battery_route_probe_factor,
        }
    }

    #[test]
    fn epic484_5_mobile_status_default_says_foreground_no_throttle() {
        // Non-mobile node: defaults — bg mode off, multiplier 1
        // (factor 1 = no scaling), AC sentinel battery 100, no
        // threshold configured. Operator sees "everything at
        // baseline" с no scaling activity.
        let r = render_mobile_status(&sample_mobile_status(false, 1, 1, 100, None, 4, 1));
        let bg_line = r.lines().find(|l| l.contains("background mode")).unwrap();
        assert!(
            bg_line.contains("inactive"),
            "default-config bg row must say inactive: {bg_line}"
        );
        assert!(
            bg_line.contains("foreground"),
            "must explain implication (foreground cadence): {bg_line}"
        );
        let bat_line = r.lines().find(|l| l.contains("battery level")).unwrap();
        assert!(
            bat_line.contains("AC / unknown"),
            "battery 100 must surface AC sentinel hint: {bat_line}"
        );
        let cfg_line = r.lines().find(|l| l.contains("battery config")).unwrap();
        assert!(
            cfg_line.contains("DISABLED"),
            "missing threshold must surface DISABLED: {cfg_line}"
        );
    }

    #[test]
    fn epic484_5_mobile_status_active_background_shows_factor_visibly() {
        // Mobile profile defaults (multiplier=60) + bg mode active
        // → factor 60. Renderer must show "ACTIVE — keepalive
        // intervals stretched by 60×" so operator sees concrete
        // scaling, not just "ACTIVE" alone.
        let r = render_mobile_status(&sample_mobile_status(true, 60, 60, 100, Some(30), 4, 1));
        let bg_line = r.lines().find(|l| l.contains("background mode")).unwrap();
        assert!(
            bg_line.contains("ACTIVE"),
            "ACTIVE must be uppercase для visibility: {bg_line}"
        );
        assert!(
            bg_line.contains("60×"),
            "must surface concrete multiplier (not just 'ACTIVE'): {bg_line}"
        );
    }

    #[test]
    fn epic484_5_mobile_status_below_threshold_battery_shows_route_probe_throttle() {
        // Phone at 25% with threshold=30 + multiplier=4 → battery
        // factor 4, route-probes throttled. Renderer surfaces
        // "below threshold; route-probes stretched 4×" so
        // operator sees connection between current battery и
        // observed slower route-probe cadence.
        let r = render_mobile_status(&sample_mobile_status(false, 1, 1, 25, Some(30), 4, 4));
        let bat_line = r.lines().find(|l| l.contains("battery level")).unwrap();
        assert!(
            bat_line.contains("below threshold"),
            "low battery must explicitly say 'below threshold': {bat_line}"
        );
        assert!(
            bat_line.contains("4×"),
            "must surface concrete throttle factor: {bat_line}"
        );
    }

    #[test]
    fn epic484_5_mobile_status_above_threshold_battery_shows_full_cadence() {
        // Phone at 80% with threshold=30 → above; route-probes
        // at full cadence (factor=1). Renderer must distinguish
        // from "AC sentinel" case (battery=100) — operator on
        // 80% wants to know "yes my readings are real, just
        // above threshold" not "non-Linux fallback".
        let r = render_mobile_status(&sample_mobile_status(false, 1, 1, 80, Some(30), 4, 1));
        let bat_line = r.lines().find(|l| l.contains("battery level")).unwrap();
        assert!(
            bat_line.contains("above threshold"),
            "above-threshold battery must explicitly say so: {bat_line}"
        );
        assert!(
            bat_line.contains("full cadence"),
            "must explain implication (no throttling at full cadence): {bat_line}"
        );
    }

    #[test]
    fn epic484_5_mobile_status_clamping_caps_documented_in_output() {
        // Operator sees the MAX cap inline so they understand why
        // an absurd misconfig gets clamped. Verify both caps
        // appear в output (background MAX=120, battery MAX=16).
        let r = render_mobile_status(&sample_mobile_status(true, 60, 60, 50, Some(30), 4, 1));
        assert!(
            r.contains("MAX=120"),
            "background MAX cap must appear для operator awareness: {r}"
        );
        assert!(
            r.contains("MAX=16"),
            "battery MAX cap must appear для operator awareness: {r}"
        );
    }

    #[test]
    fn epic484_5_update_status_mobile_background_mode_active_visible() {
        // GUI tray icon needs to render "background mode active"
        // indicator so user knows their cellular keepalive is
        // stretched. Verify this surfaces in the status text.
        let r = render_update_status(&sample_update_status(
            true,
            true,
            1,
            Some(86_400),
            Some(1_700_000_000),
            true,
        ));
        let bg_line = r
            .lines()
            .find(|l| l.contains("mobile bg mode"))
            .unwrap_or_else(|| panic!("mobile bg row missing: {r}"));
        assert!(
            bg_line.contains("ACTIVE"),
            "active background mode must be uppercase ACTIVE for visibility: {bg_line}"
        );
        assert!(
            bg_line.contains("preserved"),
            "must explain implication (sessions preserved): {bg_line}"
        );
    }

    /// empty list shows actionable hint, not just blank.
    #[test]
    fn render_mesh_status_empty_shows_hint() {
        let rendered = render_mesh_status(&[]);
        assert!(
            rendered.contains("no auto-discovered gateways"),
            "got: {rendered}"
        );
        assert!(
            rendered.contains("[mesh]"),
            "should hint at the [mesh] config section: {rendered}"
        );
    }

    /// typical row formats RTT/battery/age columns.
    #[test]
    fn render_mesh_status_formats_active_and_standby_rows() {
        let entries = vec![
            node::AdminMeshGatewayEntry {
                node_id: "aa".repeat(32),
                veil_addr: "tcp://10.0.0.1:9000".to_owned(),
                is_active: true,
                rtt_smoothed_ms: Some(42),
                battery_level: 87,
                last_seen_secs_ago: 4,
                expires_in_secs: 56,
            },
            node::AdminMeshGatewayEntry {
                node_id: "bb".repeat(32),
                veil_addr: "tcp://10.0.0.2:9000".to_owned(),
                is_active: false,
                rtt_smoothed_ms: None,
                battery_level: 0, // AC
                last_seen_secs_ago: 12,
                expires_in_secs: 48,
            },
        ];
        let rendered = render_mesh_status(&entries);
        assert!(
            rendered.contains("ACTIVE"),
            "active row missing: {rendered}"
        );
        assert!(
            rendered.contains("stdby"),
            "standby row missing: {rendered}"
        );
        assert!(rendered.contains("42ms"), "RTT not rendered: {rendered}");
        assert!(rendered.contains("87%"), "battery not rendered: {rendered}");
        assert!(
            rendered.contains("AC"),
            "battery=0 should render as AC: {rendered}"
        );
        assert!(
            rendered.contains("?"),
            "unknown RTT should render as ?: {rendered}"
        );
        assert!(
            rendered.contains("aaaaaaaaaaaaaaaa"),
            "first 16 hex chars of id1"
        );
        assert!(
            rendered.contains("bbbbbbbbbbbbbbbb"),
            "first 16 hex chars of id2"
        );
        // Header line present.
        assert!(rendered.contains("STATUS"), "header missing: {rendered}");
    }

    #[test]
    fn renders_listens_table() {
        let rendered = render_listens(&[node::AdminListenEntry {
            listen_id: "0x00000001".to_owned(),
            listener_handle: Some("0x0000000000000001".to_owned()),
            transport: "tcp://127.0.0.1:0".to_owned(),
            local_addr: Some("127.0.0.1:9000".to_owned()),
            active: true,
        }]);

        assert!(rendered.contains("listen_id"));
        assert!(rendered.contains("listener_handle"));
        assert!(rendered.contains("0x00000001"));
    }

    #[test]
    fn node_show_prints_summary_via_admin_socket() {
        let path = save_config("node-cmd-show", config_with_admin()).expect("config saves");
        let loaded = veil_cfg::load_config(&path).expect("config loads");
        let socket = node::admin_socket_path(&loaded, path.parent()).expect("admin socket path");
        let server = std::thread::spawn({
            let path = path.clone();
            move || {
                let runtime =
                    build_runtime(&veil_cfg::GlobalConfig::default()).expect("tokio runtime");
                runtime
                    .block_on(node::run_foreground(&path, true))
                    .expect("foreground node");
            }
        });
        wait_for_socket(&socket);

        let mut context = CommandContext {
            config_arg: Some(path.as_path()),
            io: BufferIo::default(),
            ops: MockConfigOps {
                locate_path: path.clone(),
                loaded_config: loaded,
                ..MockConfigOps::default()
            },
        };

        request_node_command(&mut context, node::AdminCommand::Show).expect("show succeeds");
        assert!(context.io.output.contains("node_id:"));
        assert!(context.io.output.contains("admin_socket:"));

        let runtime = build_runtime(&veil_cfg::GlobalConfig::default()).expect("tokio runtime");
        runtime
            .block_on(node::send_request(&socket, node::AdminCommand::Stop))
            .expect("stop succeeds");
        server.join().expect("server joins");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn node_show_reflects_background_mode_runtime() {
        let path =
            save_config("node-cmd-show-background", config_with_admin()).expect("config saves");
        let loaded = veil_cfg::load_config(&path).expect("config loads");
        let socket = node::admin_socket_path(&loaded, path.parent()).expect("admin socket path");
        let server = std::thread::spawn({
            let path = path.clone();
            move || {
                let runtime =
                    build_runtime(&veil_cfg::GlobalConfig::default()).expect("tokio runtime");
                runtime
                    .block_on(node::run_foreground(&path, false))
                    .expect("background-mode node runtime");
            }
        });
        wait_for_socket(&socket);

        let mut context = CommandContext {
            config_arg: Some(path.as_path()),
            io: BufferIo::default(),
            ops: MockConfigOps {
                locate_path: path.clone(),
                loaded_config: loaded,
                ..MockConfigOps::default()
            },
        };

        request_node_command(&mut context, node::AdminCommand::Show).expect("show succeeds");
        assert!(context.io.output.contains("foreground: false"));

        let runtime = build_runtime(&veil_cfg::GlobalConfig::default()).expect("tokio runtime");
        runtime
            .block_on(node::send_request(&socket, node::AdminCommand::Stop))
            .expect("stop succeeds");
        server.join().expect("server joins");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn wait_for_background_node_succeeds_when_admin_socket_becomes_ready() {
        let path =
            save_config("node-cmd-background-wait", config_with_admin()).expect("config saves");
        let loaded = veil_cfg::load_config(&path).expect("config loads");
        let socket = node::admin_socket_path(&loaded, path.parent()).expect("admin socket path");
        let server = std::thread::spawn({
            let path = path.clone();
            move || {
                let runtime =
                    build_runtime(&veil_cfg::GlobalConfig::default()).expect("tokio runtime");
                runtime
                    .block_on(node::run_foreground(&path, false))
                    .expect("background-mode node runtime");
            }
        });

        // Cross-platform ~7-second dummy child: the test only needs a live
        // `Child` handle so `wait_for_background_node` can verify it didn't
        // exit prematurely while polling the admin socket.
        #[cfg(unix)]
        let mut child = Command::new("/bin/sleep")
            .arg("7")
            .spawn()
            .expect("dummy child spawns");
        // NB: `timeout` is NOT usable here — it aborts immediately with "Input
        // redirection is not supported" when stdin isn't a console (the case
        // under the test harness), so it would exit(1) before the socket poll
        // and fail the test. `ping` waits ~1s per echo without touching stdin;
        // 8 echoes ≈ 7s comfortably outlive the 5s readiness deadline.
        #[cfg(not(unix))]
        let mut child = Command::new("ping")
            .args(["-n", "8", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("dummy child spawns");
        wait_for_background_node(&socket, &mut child).expect("background node becomes ready");
        let runtime = build_runtime(&veil_cfg::GlobalConfig::default()).expect("tokio runtime");
        let response = runtime
            .block_on(node::send_request(&socket, node::AdminCommand::Show))
            .expect("show succeeds");
        assert!(response.error.is_none());

        runtime
            .block_on(node::send_request(&socket, node::AdminCommand::Stop))
            .expect("stop succeeds");
        let _ = child.kill();
        let _ = child.wait();
        server.join().expect("server joins");
        let _ = fs::remove_file(path);
    }

    fn wait_for_socket(socket: &Path) {
        // For Unix endpoints `socket` is the socket file itself. For TCP
        // endpoints (Windows default) it's a synthetic anchor path that
        // never exists on disk — but the server writes the `admin.port`
        // sidecar to the same parent directory once the listener is bound
        // so polling for either is a portable readiness check.
        let port_sidecar = socket
            .parent()
            .map(|p| p.join("admin.port"))
            .unwrap_or_default();
        let start = std::time::Instant::now();
        while !socket.exists() && !port_sidecar.exists() {
            assert!(start.elapsed() < std::time::Duration::from_secs(2));
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    fn config_with_admin() -> Config {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let identity = test_support::valid_identity();
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        // On Unix, use a unique unix-socket; on Windows fall back to a TCP
        // loopback admin endpoint with a per-test runtime_dir so concurrent
        // tests don't collide on `admin.port` / `admin.token` sidecars.
        // Include the process id and a nanosecond timestamp so re-runs don't
        // pick up stale `admin.port` written by a previous (crashed) binary
        // — that file would point at a long-dead TCP port and connect would
        // be refused. Also matters under `cargo nextest` which runs each
        // test in its own process: `static COUNTER` resets to 0 in every
        // process, so without pid+nanos two parallel processes would both
        // pick `veil-node-cmd-0.sock` and the second `bind` would fail.
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        #[cfg(unix)]
        let admin_socket = {
            let socket =
                std::env::temp_dir().join(format!("veil-node-cmd-{pid}-{nanos}-{unique}.sock"));
            // Wipe any stale socket file from a previous crashed run; bind
            // would otherwise fail with `Address already in use`.
            let _ = std::fs::remove_file(&socket);
            format!("unix://{}", socket.display())
        };
        #[cfg(not(unix))]
        let admin_socket = {
            let runtime_dir =
                std::env::temp_dir().join(format!("veil-node-cmd-{pid}-{nanos}-{unique}"));
            // Wipe any pre-existing dir (defence in depth — directory should
            // be unique by pid+nanos, but if a race somehow recreates it the
            // stale port/token files would mislead `wait_for_socket`).
            let _ = std::fs::remove_dir_all(&runtime_dir);
            let _ = std::fs::create_dir_all(&runtime_dir);
            format!("tcp://127.0.0.1:0?runtime_dir={}", runtime_dir.display())
        };
        Config {
            global: GlobalConfig {
                admin_socket: Some(admin_socket),
                logs: LogsConfig::Stderr,
                ..GlobalConfig::default()
            },
            identity: Some(IdentityConfig {
                node_id: Some(
                    NodeId::from_public_key(identity.algo, &identity.public_key).unwrap(),
                ),
                ..identity
            }),
            peers: vec![PeerConfig {
                peer_id: PeerId::new(1),
                public_key: test_support::valid_identity().public_key,
                nonce: test_support::valid_identity().nonce,
                transport: "tcp://127.0.0.1:9000".to_owned(),
                algo: Default::default(),
                tls_cert: None,
                tls_key: None,
                tls_ca_cert: None,
                alt_uri: None,
            }],
            listen: vec![ListenConfig {
                id: ListenId::new(1),
                transport: "tcp://127.0.0.1:0".to_owned(),
                tls_cert: None,
                tls_key: None,
                tls_ca_cert: None,
                advertise: None,
                relay: None,
                ..Default::default()
            }],
            ..Config::default()
        }
    }

    fn save_config(prefix: &str, config: Config) -> veil_cfg::Result<PathBuf> {
        // was `format!("{prefix}-{unique}.toml")` without pid/nanos —
        // collided across `cargo nextest` worker processes which each reset the
        // static counter to 0. `scratch_dir` gives us 128-bit OsRng entropy +
        // pid + retry-on-EACCES, then we drop the toml file inside.
        let dir = crate::test_support::scratch_dir(&format!("veil-{prefix}"));
        let path = dir.join("config.toml");
        veil_cfg::save_config(&path, &config)?;
        Ok(path)
    }

    // ── config publish/fetch integration test ──────────────────

    // Unix-only: `publish_bundle` resolves the admin client through the
    // unix-socket DhtPut path, so on Windows this flakes with "Unix domain
    // sockets are not supported on this platform". The Windows admin transport
    // (TCP backend) is covered separately by the `windows-test` CI job's
    // `node::admin::tests::admin_tcp` + `admin_transport` tests.
    #[cfg(unix)]
    #[test]
    fn config_publish_then_fetch_roundtrips_bootstrap_bundle() {
        use crate::cmd::{
            adapters::StdConfigOps,
            handlers::{CommandContext, ConfigCommandService},
        };
        use veil_cfg::BootstrapPeer;

        // Build a config with a non-empty bootstrap_peers list and an admin
        // socket pointing at a unique per-test runtime_dir.
        let mut cfg = config_with_admin();
        // Reuse the test harness's PoW-valid identity for the bootstrap peer
        // entry — the validator requires a real 32-byte ed25519 public key
        // (base64) and a nonce that meets the configured PoW difficulty.
        let id = test_support::valid_identity();
        cfg.bootstrap_peers = vec![BootstrapPeer {
            transport: "tcp://seed-integration.example:9000".to_owned(),
            public_key: id.public_key.clone(),
            nonce: id.nonce.clone(),
            algo: id.algo,
            tls_cert: None,
            tls_ca_cert: None,
        }];
        let path = save_config("node-cmd-cfg-publish", cfg.clone()).expect("config saves");
        let loaded = veil_cfg::load_config(&path).expect("config loads");
        let socket = node::admin_socket_path(&loaded, path.parent()).expect("admin socket path");

        let server = std::thread::spawn({
            let path = path.clone();
            move || {
                let runtime =
                    build_runtime(&veil_cfg::GlobalConfig::default()).expect("tokio runtime");
                runtime
                    .block_on(node::run_foreground(&path, true))
                    .expect("foreground node");
            }
        });
        wait_for_socket(&socket);

        // Publish — uses the admin socket to do DhtPut.
        let mut ctx = CommandContext {
            config_arg: Some(path.as_path()),
            io: BufferIo::default(),
            ops: StdConfigOps,
        };
        ConfigCommandService::publish_bundle(&mut ctx).expect("publish succeeds");
        assert!(
            ctx.io.output.contains("published 1 bootstrap peer(s)"),
            "expected publish message; got: {}",
            ctx.io.output,
        );
        // bundle is now signed, advertised in the publish ack.
        assert!(
            ctx.io.output.contains("SIGNED"),
            "expected SIGNED-bundle marker in publish output; got: {}",
            ctx.io.output,
        );

        // Fetch via dry-run — reads from DHT and prints, without mutating the file.
        ctx.io.output.clear();
        ConfigCommandService::fetch_bundle(&mut ctx, true).expect("fetch succeeds");
        assert!(
            ctx.io
                .output
                .contains("fetched + verified 1 bootstrap peer(s)"),
            "expected fetch message; got: {}",
            ctx.io.output,
        );
        assert!(
            ctx.io
                .output
                .contains("tcp://seed-integration.example:9000"),
            "fetched bundle should contain the published transport URI; got: {}",
            ctx.io.output,
        );

        // follow-up: rewrite the config with a `trusted_bundle_issuer_pubkey`
        // pin set to a DIFFERENT key from the one that signed the bundle. Fetch
        // must now FAIL LOUDLY — proves the runtime-level rejection wires through
        // to the operator-visible error rather than silently accepting the
        // attacker-controlled bundle (which would happen pre-pin in no-anchor
        // mode).
        let mut pinned_cfg = veil_cfg::load_config(&path).expect("config reload");
        pinned_cfg.global.trusted_bundle_issuer_pubkey = Some(
            // Deliberately wrong pubkey — same length as the real one to
            // exercise the pubkey-byte-comparison path, not just length-rejection.
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
        );
        veil_cfg::save_config(&path, &pinned_cfg).expect("config save");

        ctx.io.output.clear();
        let pinned_result = ConfigCommandService::fetch_bundle(&mut ctx, true);
        assert!(
            pinned_result.is_err(),
            "fetch with mismatched pin must FAIL — \
             instead got Ok with output: {}",
            ctx.io.output,
        );
        let err_msg = format!("{}", pinned_result.unwrap_err());
        assert!(
            err_msg.contains("does not match pinned")
                || err_msg.contains("trusted_bundle_issuer_pubkey"),
            "pin-mismatch error must surface the \
             trusted-issuer pin name so operator knows which config field \
             to update — instead got: {err_msg}",
        );

        // Teardown — stop the node.
        let runtime = build_runtime(&veil_cfg::GlobalConfig::default()).expect("tokio runtime");
        runtime
            .block_on(node::send_request(&socket, node::AdminCommand::Stop))
            .expect("stop succeeds");
        server.join().expect("server joins");
        let _ = fs::remove_file(path);
    }
}
