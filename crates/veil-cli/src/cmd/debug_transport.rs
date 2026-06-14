use std::{
    collections::VecDeque,
    io::{self, IsTerminal as _, Read as _},
    path::Path,
    sync::Arc,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, stderr, stdout},
    sync::mpsc,
};

use veil_cfg::{self, ConfigError, Result};
use veil_transport::{
    BoxIoStream, TransportConnection, TransportContext, TransportRegistry, TransportUri,
    tls_material,
};

use super::cli::{DebugTransportCommand, DebugTransportOverrideArgs};

pub fn handle_debug_transport_command(
    config_arg: Option<&Path>,
    command: DebugTransportCommand,
) -> Result<()> {
    let runtime = super::util::build_runtime()?;
    runtime.block_on(async move { execute_debug_transport_command(config_arg, command).await })
}

async fn execute_debug_transport_command(
    config_arg: Option<&Path>,
    command: DebugTransportCommand,
) -> Result<()> {
    let registry = TransportRegistry::with_defaults();
    let (mode, ctx, uri) = prepare_debug_transport_command(config_arg, command)?;
    match mode {
        DebugMode::Connect => debug_connect(registry, ctx, uri).await,
        DebugMode::Listen => debug_listen(registry, ctx, uri).await,
    }
}

fn prepare_debug_transport_command(
    config_arg: Option<&Path>,
    command: DebugTransportCommand,
) -> Result<(DebugMode, Arc<TransportContext>, TransportUri)> {
    let (mode, transport, options) = split_debug_transport_command(command);
    let ctx = load_debug_transport_context(config_arg, options)?;
    let uri = parse_debug_transport_uri(&transport)?;
    Ok((mode, ctx, uri))
}

fn split_debug_transport_command(
    command: DebugTransportCommand,
) -> (DebugMode, String, DebugTransportOverrideArgs) {
    match command {
        DebugTransportCommand::Listen { transport, options } => {
            (DebugMode::Listen, transport, options)
        }
        DebugTransportCommand::Connect { transport, options } => {
            (DebugMode::Connect, transport, options)
        }
    }
}

fn load_debug_transport_context(
    config_arg: Option<&Path>,
    options: DebugTransportOverrideArgs,
) -> Result<Arc<TransportContext>> {
    let base_ctx = load_transport_context(config_arg).map_err(to_config_error)?;
    let ctx = apply_debug_transport_overrides(base_ctx, options).map_err(to_config_error)?;
    Ok(Arc::new(ctx))
}

fn parse_debug_transport_uri(transport: &str) -> Result<TransportUri> {
    TransportUri::parse(transport).map_err(to_config_error)
}

async fn debug_connect(
    registry: TransportRegistry,
    ctx: Arc<TransportContext>,
    uri: TransportUri,
) -> Result<()> {
    let mut input_rx = prepare_input_receiver();
    let connection = registry.connect(&uri, ctx).await.map_err(to_config_error)?;
    let _ = run_active_connection(
        connection,
        DebugMode::Connect,
        &mut input_rx,
        &mut VecDeque::new(),
    )
    .await?;
    Ok(())
}

pub(crate) async fn handle_debug_attached_stream(stream: BoxIoStream) -> Result<()> {
    let mut input_rx = prepare_input_receiver();
    let _ = pump_stream(
        stream,
        PumpMode::from_debug_mode(DebugMode::Connect),
        &mut input_rx,
        &mut VecDeque::new(),
    )
    .await?;
    Ok(())
}

async fn debug_listen(
    registry: TransportRegistry,
    ctx: Arc<TransportContext>,
    uri: TransportUri,
) -> Result<()> {
    let mut input_rx = prepare_input_receiver();
    let mut pending_input = VecDeque::new();
    let listener = bind_debug_listener(&registry, &uri, ctx).await?;

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let connection = accepted.map_err(to_config_error)?;
                match run_active_connection(
                    connection,
                    DebugMode::Listen,
                    &mut input_rx,
                    &mut pending_input,
                ).await? {
                    PumpOutcome::Restart => continue,
                    PumpOutcome::Exit => return Ok(()),
                }
            }
            maybe_input = input_rx.recv() => if let Some(outcome) = apply_idle_decision(
                &mut pending_input,
                decide_idle_listen_event(SessionEvent::Input(
                    maybe_input.unwrap_or(InputEvent::Eof),
                )),
            )? {
                return Ok(outcome);
            },
            signal = tokio::signal::ctrl_c() => {
                signal.map_err(ConfigError::Io)?;
                match apply_idle_decision(&mut pending_input, decide_idle_listen_event(SessionEvent::Signal))? {
                    Some(()) => return Ok(()),
                    // P1: clean exit instead of `unreachable!`.
                    // The invariant ("Signal cannot buffer input") is a
                    // documented FSM property, but `panic = "abort"` in
                    // release turns any future regression into a process
                    // crash for what's structurally a clean exit anyway.
                    None => return Ok(()),
                }
            }
        }
    }
}

fn prepare_input_receiver() -> mpsc::Receiver<InputEvent> {
    spawn_stdin_events()
}

const fn pump_mode(mode: DebugMode) -> PumpMode {
    PumpMode::from_debug_mode(mode)
}

async fn run_active_connection(
    connection: Box<dyn TransportConnection>,
    mode: DebugMode,
    input_rx: &mut mpsc::Receiver<InputEvent>,
    pending_input: &mut VecDeque<Vec<u8>>,
) -> Result<PumpOutcome> {
    pump_connection(connection, pump_mode(mode), input_rx, pending_input).await
}

async fn bind_debug_listener(
    registry: &TransportRegistry,
    uri: &TransportUri,
    ctx: Arc<TransportContext>,
) -> Result<Box<dyn veil_transport::TransportListener>> {
    registry.bind(uri, ctx).await.map_err(to_config_error)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DebugMode {
    Connect,
    Listen,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PumpMode {
    ExitOnCtrlC,
    RestartOnCtrlC,
}

impl PumpMode {
    const fn from_debug_mode(mode: DebugMode) -> Self {
        match mode {
            DebugMode::Connect => Self::ExitOnCtrlC,
            DebugMode::Listen => Self::RestartOnCtrlC,
        }
    }

    const fn outcome_on_disconnect(self) -> PumpOutcome {
        match self {
            Self::ExitOnCtrlC => PumpOutcome::Exit,
            Self::RestartOnCtrlC => PumpOutcome::Restart,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PumpOutcome {
    Restart,
    Exit,
}

#[derive(Debug)]
enum SessionEvent {
    Input(InputEvent),
    Connection(ConnectionEvent),
    Signal,
}

enum IdleDecision {
    BufferInput(Vec<u8>),
    AcceptConnection,
    Exit,
    Error(io::Error),
}

enum ActiveDecision {
    ForwardInput(Vec<u8>),
    ForwardOutput(Vec<u8>),
    Finish(PumpOutcome),
    Error(io::Error),
}

fn decide_idle_listen_event(event: SessionEvent) -> IdleDecision {
    match event {
        SessionEvent::Input(InputEvent::Data(data)) => IdleDecision::BufferInput(data),
        SessionEvent::Input(InputEvent::Interrupt | InputEvent::Eof) | SessionEvent::Signal => {
            IdleDecision::Exit
        }
        SessionEvent::Input(InputEvent::Error(err)) => IdleDecision::Error(err),
        SessionEvent::Connection(_) => IdleDecision::AcceptConnection,
    }
}

fn decide_active_event(mode: PumpMode, event: SessionEvent) -> ActiveDecision {
    match event {
        SessionEvent::Input(InputEvent::Data(data)) => ActiveDecision::ForwardInput(data),
        SessionEvent::Connection(ConnectionEvent::Data(data)) => {
            ActiveDecision::ForwardOutput(data)
        }
        SessionEvent::Input(InputEvent::Interrupt) | SessionEvent::Signal => {
            ActiveDecision::Finish(mode.outcome_on_disconnect())
        }
        SessionEvent::Input(InputEvent::Eof) => ActiveDecision::Finish(PumpOutcome::Exit),
        SessionEvent::Connection(ConnectionEvent::Closed) => {
            ActiveDecision::Finish(mode.outcome_on_disconnect())
        }
        SessionEvent::Input(InputEvent::Error(err))
        | SessionEvent::Connection(ConnectionEvent::Error(err)) => ActiveDecision::Error(err),
    }
}

fn apply_idle_decision(
    pending_input: &mut VecDeque<Vec<u8>>,
    decision: IdleDecision,
) -> Result<Option<()>> {
    match decision {
        IdleDecision::BufferInput(data) => {
            pending_input.push_back(data);
            Ok(None)
        }
        IdleDecision::Exit => Ok(Some(())),
        IdleDecision::Error(err) => Err(ConfigError::Io(err)),
        IdleDecision::AcceptConnection => {
            // P1: idle-listen FSM doesn't fire AcceptConnection
            // but a future state-machine change must surface that as an
            // error rather than `panic = abort` the whole process.
            Err(ConfigError::Io(std::io::Error::other(
                "idle listen FSM produced unexpected AcceptConnection event",
            )))
        }
    }
}

async fn pump_connection(
    connection: Box<dyn TransportConnection>,
    mode: PumpMode,
    input_rx: &mut mpsc::Receiver<InputEvent>,
    pending_input: &mut VecDeque<Vec<u8>>,
) -> Result<PumpOutcome> {
    emit_connection_runtime_info(connection.peer_meta()).await?;
    let stream = connection.into_stream().map_err(to_config_error)?;
    pump_stream(stream, mode, input_rx, pending_input).await
}

async fn pump_stream(
    stream: BoxIoStream,
    mode: PumpMode,
    input_rx: &mut mpsc::Receiver<InputEvent>,
    pending_input: &mut VecDeque<Vec<u8>>,
) -> Result<PumpOutcome> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (conn_tx, mut conn_rx) = mpsc::channel(256);
    tokio::spawn(async move {
        let mut buf = vec![0_u8; 8192];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => {
                    let _ = conn_tx.send(ConnectionEvent::Closed).await;
                    break;
                }
                Ok(read) => {
                    let _ = conn_tx
                        .send(ConnectionEvent::Data(buf[..read].to_vec()))
                        .await;
                }
                Err(err) => {
                    let _ = conn_tx.send(ConnectionEvent::Error(err)).await;
                    break;
                }
            }
        }
    });

    flush_pending_input(&mut writer, pending_input).await?;

    let mut output = stdout();
    loop {
        tokio::select! {
            maybe_input = input_rx.recv() => if let Some(outcome) = apply_active_decision(
                &mut writer,
                &mut output,
                decide_active_event(
                    mode,
                    SessionEvent::Input(maybe_input.unwrap_or(InputEvent::Eof)),
                ),
            ).await? {
                return Ok(outcome);
            },
            maybe_conn = conn_rx.recv() => if let Some(outcome) = apply_active_decision(
                &mut writer,
                &mut output,
                decide_active_event(
                    mode,
                    SessionEvent::Connection(maybe_conn.unwrap_or(ConnectionEvent::Closed)),
                ),
            ).await? {
                return Ok(outcome);
            },
            signal = tokio::signal::ctrl_c() => {
                signal.map_err(ConfigError::Io)?;
                match apply_active_decision(
                    &mut writer,
                    &mut output,
                    decide_active_event(mode, SessionEvent::Signal),
                ).await? {
                    Some(outcome) => return Ok(outcome),
                    // P1: clean Exit instead of `unreachable!`.
                    None => return Ok(PumpOutcome::Exit),
                }
            }
        }
    }
}

async fn flush_pending_input<W>(writer: &mut W, pending_input: &mut VecDeque<Vec<u8>>) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    while let Some(chunk) = pending_input.pop_front() {
        write_outbound_input_chunk(writer, &chunk).await?;
    }
    Ok(())
}

async fn write_outbound_input_chunk<W>(writer: &mut W, data: &[u8]) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    writer.write_all(data).await.map_err(ConfigError::Io)?;
    writer.flush().await.map_err(ConfigError::Io)?;
    Ok(())
}

async fn write_inbound_output_chunk<W>(output: &mut W, data: &[u8]) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    output.write_all(data).await.map_err(ConfigError::Io)?;
    output.flush().await.map_err(ConfigError::Io)?;
    Ok(())
}

async fn shutdown_connection_writer<W>(writer: &mut W)
where
    W: AsyncWriteExt + Unpin,
{
    let _ = writer.shutdown().await;
}

async fn apply_active_decision<W, O>(
    writer: &mut W,
    output: &mut O,
    decision: ActiveDecision,
) -> Result<Option<PumpOutcome>>
where
    W: AsyncWriteExt + Unpin,
    O: AsyncWriteExt + Unpin,
{
    match decision {
        ActiveDecision::ForwardInput(data) => {
            write_outbound_input_chunk(writer, &data).await?;
            Ok(None)
        }
        ActiveDecision::ForwardOutput(data) => {
            write_inbound_output_chunk(output, &data).await?;
            Ok(None)
        }
        ActiveDecision::Finish(outcome) => {
            shutdown_connection_writer(writer).await;
            Ok(Some(outcome))
        }
        ActiveDecision::Error(err) => {
            shutdown_connection_writer(writer).await;
            Err(ConfigError::Io(err))
        }
    }
}

#[derive(Debug)]
enum InputEvent {
    Data(Vec<u8>),
    Interrupt,
    Eof,
    Error(io::Error),
}

#[derive(Debug)]
enum ConnectionEvent {
    Data(Vec<u8>),
    Closed,
    Error(io::Error),
}

fn spawn_stdin_events() -> mpsc::Receiver<InputEvent> {
    let (tx, rx) = mpsc::channel(1024);
    std::thread::spawn(move || {
        let input = io::stdin();
        let is_terminal = input.is_terminal();
        let mut input = input.lock();
        let mut buf = vec![0_u8; 8192];
        loop {
            match input.read(&mut buf) {
                Ok(0) => {
                    let _ = tx.blocking_send(InputEvent::Eof);
                    break;
                }
                Ok(read) => {
                    let chunk = &buf[..read];
                    if is_terminal && chunk == [0x03] {
                        let _ = tx.blocking_send(InputEvent::Interrupt);
                        continue;
                    }
                    let _ = tx.blocking_send(InputEvent::Data(chunk.to_vec()));
                }
                Err(err) => {
                    if err.kind() == io::ErrorKind::Interrupted {
                        let _ = tx.blocking_send(InputEvent::Interrupt);
                        continue;
                    }
                    let _ = tx.blocking_send(InputEvent::Error(err));
                    break;
                }
            }
        }
    });
    rx
}

async fn emit_connection_runtime_info(peer: &veil_transport::PeerMeta) -> Result<()> {
    let Some(runtime) = &peer.runtime_info else {
        return Ok(());
    };
    let mut err = stderr();
    let line = format!(
        "[transport] scheme={} handshake={:?} remote={}\n",
        peer.scheme, runtime.handshake_mode, peer.description,
    );
    err.write_all(line.as_bytes())
        .await
        .map_err(ConfigError::Io)?;
    err.flush().await.map_err(ConfigError::Io)?;
    Ok(())
}

fn to_config_error(err: impl ToString) -> ConfigError {
    ConfigError::Io(io::Error::other(err.to_string()))
}

fn load_transport_context(config_arg: Option<&Path>) -> Result<TransportContext> {
    match veil_cfg::locate_config(config_arg) {
        Ok(path) => {
            let config = veil_cfg::load_config(&path)?;
            veil_cfg::transport_glue::context_from_config(&config).map_err(to_config_error)
        }
        Err(veil_cfg::ConfigError::NotFound) => {
            TransportContext::for_debug().map_err(to_config_error)
        }
        Err(err) => Err(err),
    }
}

fn apply_debug_transport_overrides(
    mut ctx: TransportContext,
    options: DebugTransportOverrideArgs,
) -> veil_transport::Result<TransportContext> {
    ctx = apply_debug_tls_ca_override(ctx, options.tls.tls_ca_cert.as_deref())?;
    ctx = apply_debug_tls_identity_override(
        ctx,
        options.tls.tls_cert.as_deref(),
        options.tls.tls_key.as_deref(),
    )?;
    Ok(ctx)
}

fn apply_debug_tls_ca_override(
    mut ctx: TransportContext,
    tls_ca_cert: Option<&Path>,
) -> veil_transport::Result<TransportContext> {
    if let Some(ca_cert_path) = tls_ca_cert {
        let certs = tls_material::load_certificates_from_file(ca_cert_path)?;
        ctx.tls = ctx.tls.with_trusted_certificates(certs)?;
    }
    Ok(ctx)
}

fn apply_debug_tls_identity_override(
    mut ctx: TransportContext,
    tls_cert: Option<&Path>,
    tls_key: Option<&Path>,
) -> veil_transport::Result<TransportContext> {
    match (tls_cert, tls_key) {
        (None, None) => {}
        (None, Some(_)) => {
            return Err(veil_transport::TransportError::Unsupported(
                "`--tls-key` requires `--tls-cert`".to_owned(),
            ));
        }
        (Some(cert_path), None) => {
            let certs = tls_material::load_certificates_from_file(cert_path)?;
            ctx.tls = ctx.tls.with_trusted_certificates(certs)?;
        }
        (Some(cert_path), Some(key_path)) => {
            let certs = tls_material::load_certificates_from_file(cert_path)?;
            let key = tls_material::load_private_key_from_file(key_path)?;
            ctx.tls = ctx.tls.with_server_identity(certs, key)?;
        }
    }
    Ok(ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };

    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use veil_transport::{TransportContext, TransportRegistry, TransportUri};

    #[test]
    fn connect_interrupt_exits() {
        let decision = decide_active_event(
            PumpMode::from_debug_mode(DebugMode::Connect),
            SessionEvent::Input(InputEvent::Interrupt),
        );
        assert!(matches!(
            decision,
            ActiveDecision::Finish(PumpOutcome::Exit)
        ));
    }

    #[test]
    fn listen_active_interrupt_restarts() {
        let decision = decide_active_event(
            PumpMode::from_debug_mode(DebugMode::Listen),
            SessionEvent::Input(InputEvent::Interrupt),
        );
        assert!(matches!(
            decision,
            ActiveDecision::Finish(PumpOutcome::Restart)
        ));
    }

    #[test]
    fn listen_idle_eof_exits() {
        let decision = decide_idle_listen_event(SessionEvent::Input(InputEvent::Eof));
        assert!(matches!(decision, IdleDecision::Exit));
    }

    #[test]
    fn remote_close_exits_for_connect() {
        let decision = decide_active_event(
            PumpMode::from_debug_mode(DebugMode::Connect),
            SessionEvent::Connection(ConnectionEvent::Closed),
        );
        assert!(matches!(
            decision,
            ActiveDecision::Finish(PumpOutcome::Exit)
        ));
    }

    #[test]
    fn remote_close_restarts_for_listen() {
        let decision = decide_active_event(
            PumpMode::from_debug_mode(DebugMode::Listen),
            SessionEvent::Connection(ConnectionEvent::Closed),
        );
        assert!(matches!(
            decision,
            ActiveDecision::Finish(PumpOutcome::Restart)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tls_custom_server_identity_and_trusted_ca_roundtrip() {
        let tls_files = TestTlsFiles::new().expect("test tls files");

        let server_ctx = Arc::new(
            apply_debug_transport_overrides(
                TransportContext::for_debug().expect("server debug ctx"),
                DebugTransportOverrideArgs {
                    tls: crate::cmd::cli::TlsMaterialArgs {
                        tls_cert: Some(tls_files.server_cert.clone()),
                        tls_key: Some(tls_files.server_key.clone()),
                        tls_ca_cert: None,
                    },
                },
            )
            .expect("server tls overrides"),
        );
        let client_ctx = Arc::new(
            apply_debug_transport_overrides(
                TransportContext::for_debug().expect("client debug ctx"),
                DebugTransportOverrideArgs {
                    tls: crate::cmd::cli::TlsMaterialArgs {
                        tls_cert: None,
                        tls_key: None,
                        tls_ca_cert: Some(tls_files.ca_cert.clone()),
                    },
                },
            )
            .expect("client tls overrides"),
        );

        let registry = TransportRegistry::with_defaults();
        let bind_uri = TransportUri::parse("tls://127.0.0.1:0").expect("tls bind uri");
        let listener = registry
            .bind(&bind_uri, Arc::clone(&server_ctx))
            .await
            .expect("tls listener");
        let listen_addr = listener.local_addr();

        let server = tokio::spawn(async move {
            let connection = listener.accept().await.expect("server accept");
            let mut stream = connection.into_stream().expect("server stream");
            let mut buf = [0_u8; 5];
            stream.read_exact(&mut buf).await.expect("server read");
            assert_eq!(&buf, b"hello");
            stream.write_all(b"world").await.expect("server write");
            stream.shutdown().await.expect("server shutdown");
        });

        let connect_uri =
            TransportUri::parse(&format!("tls://{listen_addr}")).expect("tls connect uri");
        let connection = registry
            .connect(&connect_uri, client_ctx)
            .await
            .expect("client connect");
        let mut stream = connection.into_stream().expect("client stream");
        stream.write_all(b"hello").await.expect("client write");
        stream.flush().await.expect("client flush");
        let mut buf = [0_u8; 5];
        stream.read_exact(&mut buf).await.expect("client read");
        assert_eq!(&buf, b"world");

        server.await.expect("server join");
    }

    /// Validates the rustls-specific `CaUsedAsEndEntity` error surfaces with a
    /// useful operator hint when the user passes a CA cert where an endpoint
    /// cert is expected. Not applicable to the `tls-boring` backend: veil
    /// uses node-id binding instead of PKI chain validation, so boring-side
    /// verification is intentionally disabled and this misconfiguration would
    /// silently succeed at the TLS layer (rejected later by the session-layer
    /// identity check).
    #[cfg_attr(feature = "tls-boring", ignore = "rustls-specific PKI error path")]
    #[tokio::test(flavor = "current_thread")]
    async fn tls_custom_server_cert_role_error_is_explained() {
        let tls_files = TestTlsFiles::new().expect("test tls files");

        let server_ctx = Arc::new(
            apply_debug_transport_overrides(
                TransportContext::for_debug().expect("server debug ctx"),
                DebugTransportOverrideArgs {
                    tls: crate::cmd::cli::TlsMaterialArgs {
                        tls_cert: Some(tls_files.ca_cert.clone()),
                        tls_key: Some(tls_files.ca_key.clone()),
                        tls_ca_cert: None,
                    },
                },
            )
            .expect("server tls overrides"),
        );
        let client_ctx = Arc::new(
            apply_debug_transport_overrides(
                TransportContext::for_debug().expect("client debug ctx"),
                DebugTransportOverrideArgs {
                    tls: crate::cmd::cli::TlsMaterialArgs {
                        tls_cert: None,
                        tls_key: None,
                        tls_ca_cert: Some(tls_files.ca_cert.clone()),
                    },
                },
            )
            .expect("client tls overrides"),
        );

        let registry = TransportRegistry::with_defaults();
        let bind_uri = TransportUri::parse("tls://127.0.0.1:0").expect("tls bind uri");
        let listener = registry
            .bind(&bind_uri, Arc::clone(&server_ctx))
            .await
            .expect("tls listener");
        let listen_addr = listener.local_addr();

        let server =
            tokio::spawn(async move { listener.accept().await.err().map(|err| err.to_string()) });
        let connect_uri =
            TransportUri::parse(&format!("tls://{listen_addr}")).expect("tls connect uri");
        let err = match registry.connect(&connect_uri, client_ctx).await {
            Ok(_) => panic!("client connect must fail"),
            Err(err) => err,
        };
        let err_text = err.to_string();
        assert!(err_text.contains("CaUsedAsEndEntity"));
        assert!(err_text.contains("CA/root certificate for `--tls-ca-cert`"));

        let _ = server.await.expect("server join");
    }

    struct TestTlsFiles {
        dir: PathBuf,
        ca_cert: PathBuf,
        ca_key: PathBuf,
        server_cert: PathBuf,
        server_key: PathBuf,
    }

    impl TestTlsFiles {
        fn new() -> std::result::Result<Self, Box<dyn std::error::Error>> {
            let dir = make_temp_dir("veil-debug-tls");
            fs::create_dir_all(&dir)?;

            let ca_key = KeyPair::generate()?;
            let mut ca_params = CertificateParams::new(vec!["veil-test-ca".to_owned()])?;
            ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            ca_params
                .distinguished_name
                .push(DnType::CommonName, "veil-test-ca");
            let ca_cert = ca_params.self_signed(&ca_key)?;

            let server_key = KeyPair::generate()?;
            let mut server_params =
                CertificateParams::new(vec!["127.0.0.1".to_owned(), "localhost".to_owned()])?;
            server_params
                .distinguished_name
                .push(DnType::CommonName, "127.0.0.1");
            let server_cert = server_params.signed_by(&server_key, &ca_cert, &ca_key)?;

            let ca_cert_path = dir.join("ca.pem");
            let ca_key_path = dir.join("ca.key");
            let server_cert_path = dir.join("server.pem");
            let server_key_path = dir.join("server.key");

            write_file(&ca_cert_path, ca_cert.pem())?;
            write_file(&ca_key_path, ca_key.serialize_pem())?;
            write_file(&server_cert_path, server_cert.pem())?;
            write_file(&server_key_path, server_key.serialize_pem())?;

            Ok(Self {
                dir,
                ca_cert: ca_cert_path,
                ca_key: ca_key_path,
                server_cert: server_cert_path,
                server_key: server_key_path,
            })
        }
    }

    impl Drop for TestTlsFiles {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn make_temp_dir(prefix: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{unique}"))
    }

    fn write_file(path: &Path, contents: String) -> io::Result<()> {
        fs::write(path, contents)
    }
}
