//! `oproxy-server` — standalone proxy exit binary.
//!
//! Binds an veil app endpoint via the local daemon's IPC socket
//! (using the **inbound-stream accept** SDK API shipped в Phase 6.51),
//! accepts incoming veil streams, и для each one:
//!
//! 1. Checks the source `node_id` against the configured allowlist.
//!    Empty allowlist ⇒ allow-all (open proxy).
//! 2. Reads the connect header (`[host_len u16][host][port u16]`).
//! 3. Validates the destination is not RFC1918 / loopback /
//!    multicast / metadata (unless `allow_private = true`).
//! 4. Opens а TCP outbound к `host:port`.
//! 5. Replies с а status byte и bridges bytes duplex.
//!
//! Run:
//!   oproxy-server --config /etc/oproxy/server.toml

// oproxy-server depends on `veilclient::VeilClient`, which is
// itself `#[cfg(unix)]`-gated (Unix-domain socket IPC).  Wrap the
// entire bin content в а `#[cfg(unix)] mod imp` so cross-compile к
// x86_64-pc-windows-gnu doesn't trip on the unresolved `AppSender`
// import от oproxy::connector.  Windows stub main exits с error.
#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    eprintln!("oproxy-server is not supported on this platform (Unix-family only).");
    std::process::ExitCode::FAILURE
}

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    imp::main()
}

#[cfg(unix)]
mod imp {
    use std::net::IpAddr;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::{Context, Result, anyhow};
    use clap::Parser;
    use tokio::io::{AsyncWriteExt, copy};
    use tokio::net::{TcpStream, lookup_host};
    use tokio::time::timeout;

    use veilclient::VeilClient;

    use oproxy::app_cert_gate::AppCertGate;
    use oproxy::authz::NodeAllowlist;
    use oproxy::config::ServerConfig;
    use oproxy::wire::{
        ConnectStatus, StreamPrefix, read_connect_header_with_peeked_hi, read_stream_prefix,
        write_status,
    };
    use veil_cfg::build_tokio_runtime;

    #[derive(Parser, Debug)]
    #[command(version, about = "Veil-network proxy exit server")]
    struct Args {
        /// Path к а TOML config file (см. `crates/oproxy/README.md`).
        #[arg(long, value_name = "PATH", required_unless_present = "gen_config")]
        config: Option<PathBuf>,

        /// Print а commented default-config TOML template к stdout и exit.
        /// Operators run this once, redirect к а file, edit the placeholders,
        /// then start с `--config <path>`.
        ///
        /// Example:
        ///   oproxy-server --gen-config > /etc/oproxy/server.toml
        #[arg(long, conflicts_with = "config")]
        gen_config: bool,
    }

    const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    pub fn main() -> std::process::ExitCode {
        let args = Args::parse();
        if args.gen_config {
            use std::io::Write;
            let stdout = std::io::stdout();
            if let Err(e) = stdout
                .lock()
                .write_all(oproxy::config_template::SERVER_DEFAULT_CONFIG.as_bytes())
            {
                eprintln!("oproxy-server: write default config: {e}");
                return std::process::ExitCode::FAILURE;
            }
            return std::process::ExitCode::SUCCESS;
        }
        // `required_unless_present` guarantees Some(_) when not in --gen-config mode.
        let config_path = args
            .config
            .expect("clap should have required --config when --gen-config absent");
        // Audit batch 2026-05-24 (M6): warn если config file is loose-mode.
        oproxy::config::warn_loose_config_perms(&config_path);
        let raw = match std::fs::read_to_string(&config_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("oproxy-server: read {}: {e}", config_path.display());
                return std::process::ExitCode::FAILURE;
            }
        };
        let cfg: ServerConfig = match toml::from_str(&raw) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("oproxy-server: parse {}: {e}", config_path.display());
                return std::process::ExitCode::FAILURE;
            }
        };

        if let Err(e) = oproxy::init_oproxy_logger("oproxy-server", &cfg.logging) {
            eprintln!("oproxy-server: failed to init logger: {e}");
            return std::process::ExitCode::FAILURE;
        }

        let mut rt_cfg = cfg.runtime.clone();
        rt_cfg.apply_env_overrides("OPROXY");
        let rt = match build_tokio_runtime(&rt_cfg) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("oproxy-server: failed to build tokio runtime: {e}");
                return std::process::ExitCode::FAILURE;
            }
        };

        rt.block_on(async move {
            match run(cfg).await {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("oproxy-server: {e}");
                    std::process::ExitCode::FAILURE
                }
            }
        })
    }

    async fn run(cfg: ServerConfig) -> Result<()> {
        let allowlist = NodeAllowlist::from_hex_list(&cfg.allowed_node_ids)
            .map_err(|e| anyhow!("allowed_node_ids: {e}"))?;

        // Audit batch 2026-05-24 (M11): refuse silent open-proxy.  Operator
        // must explicitly set `allow_all = true` к acknowledge what they're
        // running.  This catches the common "empty list means restrictive"
        // misconception ДО the daemon starts taking traffic.
        if !allowlist.is_restrictive() && !cfg.allow_all {
            anyhow::bail!(
                "oproxy-server: refusing к start as open proxy.  Either:\n  \
              • Populate `allowed_node_ids = [\"<hex>\", ...]` к gate \
                callers, OR\n  \
              • Set `allow_all = true` explicitly к acknowledge open-\
                proxy semantics (any veil peer can use this server)."
            );
        }
        if !allowlist.is_restrictive() && cfg.allow_all {
            log::warn!(
                "oproxy-server: starting as OPEN PROXY (allow_all=true, no allowlist). \
             Any veil peer can use this server для outbound TCP."
            );
        }

        log::info!(
            "oproxy-server: starting (app_name={}, allowlist={}, allow_private={})",
            cfg.app_name,
            if allowlist.is_restrictive() {
                format!("strict ({} ids)", allowlist.size())
            } else {
                "allow-all (explicit allow_all=true)".to_string()
            },
            cfg.allow_private,
        );

        let client = VeilClient::connect(&cfg.socket_path)
            .await
            .with_context(|| format!("connect to veil daemon at {}", cfg.socket_path.display()))?;
        // `bind_named` (not `bind`) — required for stable deterministic
        // app_id derivation.  Clients compute the SAME app_id via
        // `veil_app::address::app_id(server_node_id, namespace, name)`
        // и use it as the dst_app_id in their `open_stream` calls.
        // `bind` would assign а random ephemeral app_id что the client
        // cannot reproduce, so opens would fail с NOT_FOUND.
        let mut app = client
            .bind_named(oproxy::SERVER_NAMESPACE, &cfg.app_name, 0)
            .await
            .context("bind_named oproxy server endpoint")?;
        let app_id = *app.app_id();
        log::info!(
            "oproxy-server: bound endpoint app_id={:02x}{:02x}{:02x}{:02x}.. endpoint_id=0",
            app_id[0],
            app_id[1],
            app_id[2],
            app_id[3],
        );

        let allowlist = Arc::new(allowlist);
        let allow_private = cfg.allow_private;
        let pnet_required = cfg.pnet_required;
        // Arc-wrap the client so each spawned handler holds а handle for
        // its own `peer_pnet_status` calls when pnet_required.  All clones
        // share the same dispatcher / IPC writer underneath.
        let client = Arc::new(client);

        // S2.B: build app-cert gate если operator configured all three fields.
        // Partial config (e.g. owner_pubkey set но network_id missing) fails
        // startup — better than silently downgrading к no-gate semantics.
        let app_cert_gate: Option<Arc<AppCertGate>> = match (
            &cfg.app_cert_trusted_owner_pubkey,
            cfg.app_cert_owner_algo,
            &cfg.app_cert_network_id,
        ) {
            (Some(pk), Some(algo), Some(nid)) => {
                let gate = AppCertGate::from_config(pk, algo, nid)
                    .context("build AppCertGate from app_cert_* config")?;
                log::info!("oproxy-server: app-cert gate active (network_id={nid})");
                Some(Arc::new(gate))
            }
            (None, None, None) => None,
            _ => {
                anyhow::bail!(
                    "oproxy-server: app_cert_trusted_owner_pubkey + app_cert_owner_algo + \
                 app_cert_network_id must all be set together (or none of them)."
                );
            }
        };

        // Audit batch 2026-05-24 (M8): cap concurrent veil streams.  When
        // at capacity, accept_stream() blocks; daemon backpressures upstream
        // peers via the standard stream-window mechanism.
        let max_streams = cfg.limits.max_concurrent_streams;
        log::info!("oproxy-server: max_concurrent_streams={max_streams}");
        let stream_sem = Arc::new(tokio::sync::Semaphore::new(max_streams));

        // Accept loop — для each incoming veil stream, spawn а handler.
        loop {
            let permit = match Arc::clone(&stream_sem).acquire_owned().await {
                Ok(p) => p,
                Err(_closed) => {
                    log::warn!("oproxy-server: semaphore closed; exiting");
                    break;
                }
            };
            let incoming = match app.accept_stream().await {
                Some(s) => s,
                None => {
                    log::warn!("oproxy-server: accept_stream closed (daemon disconnect?); exiting");
                    break;
                }
            };
            let src = incoming.src_node_id;
            log::debug!(
                "oproxy-server: accept stream от node_id={:02x}{:02x}..",
                src[0],
                src[1],
            );

            let allowlist = Arc::clone(&allowlist);
            let client_for_handler = Arc::clone(&client);
            let gate_for_handler = app_cert_gate.as_ref().map(Arc::clone);
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = handle_stream(
                    incoming,
                    allowlist,
                    allow_private,
                    pnet_required,
                    client_for_handler,
                    gate_for_handler,
                )
                .await
                {
                    log::debug!(
                        "oproxy-server: stream от {:02x}{:02x}.. closed: {e}",
                        src[0],
                        src[1],
                    );
                }
            });
        }
        Ok(())
    }

    async fn handle_stream(
        incoming: veilclient::IncomingStream,
        allowlist: Arc<NodeAllowlist>,
        allow_private: bool,
        pnet_required: bool,
        client: Arc<VeilClient>,
        app_cert_gate: Option<Arc<AppCertGate>>,
    ) -> Result<()> {
        let mut stream = incoming.stream;
        let src = incoming.src_node_id;

        // Authz check first — fail-closed.  Cheaper than reading the
        // header for а peer we'd reject anyway.
        if !allowlist.permits(&src) {
            log::info!(
                "oproxy-server: deny node_id={:02x}{:02x}{:02x}{:02x}.. (not в allowlist)",
                src[0],
                src[1],
                src[2],
                src[3]
            );
            write_status(&mut stream, ConnectStatus::Denied).await.ok();
            return Ok(());
        }

        // S2.A P-Net check: when `pnet_required = true`, query the daemon's
        // verified-cert cache.  Reject если peer has no valid
        // MembershipCert.  Local IPC round-trip — sub-millisecond cost on
        // а warm daemon.  Cache на the daemon side means repeat queries
        // для the same peer don't burn CPU.
        if pnet_required {
            match client.peer_pnet_status(&src).await {
                Ok(status) => {
                    if !(status.admitted && status.has_cert) {
                        log::info!(
                            "oproxy-server: deny node_id={:02x}{:02x}{:02x}{:02x}.. \
                         (pnet_required: admitted={} has_cert={})",
                            src[0],
                            src[1],
                            src[2],
                            src[3],
                            status.admitted,
                            status.has_cert,
                        );
                        write_status(&mut stream, ConnectStatus::Denied).await.ok();
                        return Ok(());
                    }
                }
                Err(e) => {
                    // Daemon RPC failed — fail-closed.  Operator's choice к
                    // run в p_net mode means они want the strict gate; if it
                    // can't be evaluated, deny rather than fall-back-open.
                    log::warn!(
                        "oproxy-server: pnet_status query failed для {:02x}{:02x}..: {e}; denying",
                        src[0],
                        src[1]
                    );
                    write_status(&mut stream, ConnectStatus::Denied).await.ok();
                    return Ok(());
                }
            }
        }

        // S2.B: read the wire prefix.  If client sent an app-cert preamble,
        // optionally verify; if absent + app_cert_required → reject;
        // otherwise splice the peeked byte back into the connect-header read.
        let prefix_result = tokio::time::timeout(
            oproxy::timeouts::SERVER_CONNECT_HEADER_TIMEOUT,
            read_stream_prefix(&mut stream),
        )
        .await;
        let peeked_host_len_hi = match prefix_result {
            Ok(Ok(StreamPrefix::Cert(blob))) => {
                match app_cert_gate.as_ref() {
                    Some(gate) => match gate.verify(&blob, &src) {
                        Ok(()) => {
                            log::debug!(
                                "oproxy-server: app-cert verified для {:02x}{:02x}..",
                                src[0],
                                src[1]
                            );
                        }
                        Err(e) => {
                            log::info!(
                                "oproxy-server: deny {:02x}{:02x}.. (app-cert verify failed: {e})",
                                src[0],
                                src[1]
                            );
                            write_status(&mut stream, ConnectStatus::Denied).await.ok();
                            return Ok(());
                        }
                    },
                    None => {
                        // Client presented cert но server isn't configured к verify.
                        // Accept silently — wire-compat для mixed-deployment migration.
                        log::debug!(
                            "oproxy-server: ignoring unsolicited app-cert от {:02x}{:02x}.. (gate not configured)",
                            src[0],
                            src[1]
                        );
                    }
                }
                // Cert path: connect header follows immediately, no peeked byte.
                None
            }
            Ok(Ok(StreamPrefix::NoPreamble { peeked_host_len_hi })) => {
                if app_cert_gate.is_some() {
                    log::info!(
                        "oproxy-server: deny {:02x}{:02x}.. (app_cert required, no preamble)",
                        src[0],
                        src[1]
                    );
                    write_status(&mut stream, ConnectStatus::Denied).await.ok();
                    return Ok(());
                }
                Some(peeked_host_len_hi)
            }
            Ok(Err(e)) => {
                log::debug!("oproxy-server: bad stream prefix: {e}");
                write_status(&mut stream, ConnectStatus::BadRequest)
                    .await
                    .ok();
                return Err(e.into());
            }
            Err(_) => {
                log::debug!("oproxy-server: stream prefix read timeout");
                return Ok(());
            }
        };

        // Audit batch 2026-05-24: wrap connect-header read в timeout — а
        // slow / never-terminating peer cannot tie up the accept-loop's
        // worker indefinitely.
        let read_header_fut = async {
            match peeked_host_len_hi {
                Some(hi) => read_connect_header_with_peeked_hi(&mut stream, hi).await,
                None => {
                    // Cert-preamble path consumed nothing после the cert —
                    // host_len_hi byte is fresh on the wire.
                    let mut hi = [0u8; 1];
                    tokio::io::AsyncReadExt::read_exact(&mut stream, &mut hi).await?;
                    read_connect_header_with_peeked_hi(&mut stream, hi[0]).await
                }
            }
        };
        let (host, port) = match tokio::time::timeout(
            oproxy::timeouts::SERVER_CONNECT_HEADER_TIMEOUT,
            read_header_fut,
        )
        .await
        {
            Ok(Ok(hp)) => hp,
            Ok(Err(e)) => {
                log::debug!("oproxy-server: bad connect header: {e}");
                write_status(&mut stream, ConnectStatus::BadRequest)
                    .await
                    .ok();
                return Err(e.into());
            }
            Err(_) => {
                log::debug!("oproxy-server: connect header read timeout");
                write_status(&mut stream, ConnectStatus::BadRequest)
                    .await
                    .ok();
                return Err(anyhow!("connect-header read timeout"));
            }
        };

        // Resolve + filter destination.
        let addrs: Vec<std::net::SocketAddr> = lookup_host((host.as_str(), port))
            .await
            .map(|it| it.collect())
            .unwrap_or_default();
        if addrs.is_empty() {
            log::debug!("oproxy-server: DNS resolve {host}:{port} returned empty");
            write_status(&mut stream, ConnectStatus::ConnectFailed)
                .await
                .ok();
            return Err(anyhow!("DNS resolve {host}:{port} empty"));
        }
        if !allow_private {
            for addr in &addrs {
                if is_forbidden(addr.ip()) {
                    log::info!(
                        "oproxy-server: deny dst {host}:{port} → {} (forbidden network)",
                        addr.ip()
                    );
                    write_status(&mut stream, ConnectStatus::Denied).await.ok();
                    return Ok(());
                }
            }
        }

        // TCP outbound.
        let mut tcp = match timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(&addrs[0])).await {
            Ok(Ok(t)) => t,
            Ok(Err(e)) => {
                log::debug!("oproxy-server: connect {} failed: {e}", addrs[0]);
                write_status(&mut stream, ConnectStatus::ConnectFailed)
                    .await
                    .ok();
                return Err(e.into());
            }
            Err(_) => {
                log::debug!("oproxy-server: connect {} timed out", addrs[0]);
                write_status(&mut stream, ConnectStatus::ConnectFailed)
                    .await
                    .ok();
                return Err(anyhow!("timeout connecting to {}", addrs[0]));
            }
        };

        // Status reply OK, then bridge.
        write_status(&mut stream, ConnectStatus::Ok)
            .await
            .context("write OK status")?;

        let (mut tcp_r, mut tcp_w) = tcp.split();
        let (mut stream_r, mut stream_w) = tokio::io::split(stream);
        let up = async {
            let _ = copy(&mut stream_r, &mut tcp_w).await;
            let _ = tcp_w.shutdown().await;
        };
        let down = async {
            let _ = copy(&mut tcp_r, &mut stream_w).await;
            let _ = stream_w.shutdown().await;
        };
        tokio::join!(up, down);
        Ok(())
    }

    /// Reject loopback / private / multicast / metadata destinations.
    /// audit cycle-6 (A9): delegate to the shared `oproxy::routing::is_forbidden_ip`
    /// (which carries the CRITICAL audit-2026-05-29 IPv4-mapped-IPv6 fix) so the
    /// server bin and the client `Direct` path cannot drift out of sync.
    fn is_forbidden(ip: IpAddr) -> bool {
        oproxy::routing::is_forbidden_ip(ip)
    }
} // end mod imp (cfg unix)
