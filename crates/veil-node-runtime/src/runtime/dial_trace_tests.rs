//! The real NodeServices boundary must assign one local context per dial,
//! clear inherited metadata while off, and record only an expected local slot.
use super::tests::{resumption_leaf_identity, runtime_config_with_listen, save_test_config};
use super::*;
use futures::{FutureExt, future::BoxFuture};
use veil_transport::{
    Transport, TransportCapabilities, TransportConnection, TransportListener, TransportUri,
};

struct ObserveDial(Arc<Mutex<Vec<Option<u64>>>>);
impl Transport for ObserveDial {
    fn scheme(&self) -> &'static str {
        "tcp"
    }
    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities::stream_connection()
    }
    fn connect<'a>(
        &'a self,
        _: &'a TransportUri,
        ctx: Arc<TransportContext>,
    ) -> BoxFuture<'a, veil_transport::Result<Box<dyn TransportConnection>>> {
        Box::pin(async move {
            self.0
                .lock()
                .unwrap()
                .push(ctx.tracing.tcp_connect_context().map(|c| c.local_id()));
            Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused).into())
        })
    }
    fn bind<'a>(
        &'a self,
        _: &'a TransportUri,
        _: Arc<TransportContext>,
    ) -> BoxFuture<'a, veil_transport::Result<Box<dyn TransportListener>>> {
        Box::pin(async { unreachable!("dial observer creates no sockets") })
    }
}

#[tokio::test]
async fn dial_context_is_fresh_operator_gated_and_maps_only_the_expected_slot() {
    let identity = resumption_leaf_identity();
    let mut config = runtime_config_with_listen();
    config.peers.clear();
    config.bootstrap_peers.clear();
    config.listen.clear();
    config.global.meeting_points = veil_cfg::MeetingPoints::Only(Vec::new());
    config.global.builtin_seed_policy = veil_cfg::BuiltinSeedPolicy::Never;
    config.pex.enabled = false;
    config.identity.as_mut().unwrap().lazy_mining = false;
    let path = save_test_config("dial-context", config).unwrap();
    let mut runtime = NodeRuntime::start(&path, true).await.unwrap();
    let mut services = runtime.access();
    let log_path = path.parent().unwrap().join("operator.log");
    services.logger = Arc::new(
        veil_observability::NodeLogger::from_parts(
            veil_types::LogsConfig::File,
            Some(&log_path),
            veil_types::LogLevel::Info,
            veil_types::LogFormat::Text,
        )
        .unwrap(),
    );
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut registry = veil_transport::TransportRegistry::new();
    registry.register(Arc::new(ObserveDial(seen.clone())));
    services.registry = Arc::new(registry);
    let peer_id = PeerId::new(0x77);
    services.state.lock().unwrap().peers.insert(
        peer_id,
        crate::types::PeerConfigEntry {
            peer_id,
            node_id: identity.node_id,
            public_key: identity.public_key.clone(),
            nonce: identity.nonce.clone(),
            algo: identity.algo,
            transport: "tcp://127.0.0.1:9".to_owned(),
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            bootstrap_only: true,
            source: crate::types::PeerSource::Bootstrap,
        },
    );
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            veil_transport::tcp_trace::set_enabled(self.0);
        }
    }
    let restore = Restore(veil_transport::tcp_trace::is_enabled());
    let outcome = std::panic::AssertUnwindSafe(async {
        veil_transport::tcp_trace::set_enabled(true);
        let inherited = veil_transport::tcp_trace::ConnectTraceContext::new_if_enabled().unwrap();
        let mut base = (*services.transport_ctx).clone();
        base.tracing.set_tcp_connect_context(Some(inherited));
        services.transport_ctx = Arc::new(base);
        // DebugAttached never starts NAT/proxy fallback after our synthetic
        // refusal. This exercises the real facade without opening any socket.
        veil_transport::tcp_trace::set_enabled(false);
        assert!(services.connect_peer(peer_id).await.is_err());
        veil_transport::tcp_trace::set_enabled(true);
        assert!(services.connect_peer(peer_id).await.is_err());
        assert!(services.connect_peer(peer_id).await.is_err());
        veil_transport::tcp_trace::set_enabled(false);
        assert!(services.connect_peer(peer_id).await.is_err());
        let contexts = seen.lock().unwrap().clone();
        assert_eq!(contexts.len(), 4);
        assert_eq!(contexts[0], None);
        assert_eq!(contexts[3], None);
        let first = contexts[1].unwrap();
        let second = contexts[2].unwrap();
        assert_ne!(first, second);
        assert_ne!(first, inherited.local_id());
        assert_ne!(second, inherited.local_id());
        let log = std::fs::read_to_string(&log_path).unwrap();
        let rows: Vec<_> = log
            .lines()
            .filter(|row| row.contains("transport.connect.context"))
            .collect();
        assert_eq!(rows.len(), 2);
        for (row, id) in rows.into_iter().zip([first, second]) {
            assert!(row.contains(&format!(
                "context={id} peer_slot={peer_id} scheme=tcp monotonic_us="
            )));
            assert!(!row.contains("127.0.0.1"));
            assert!(!row.contains(&identity.public_key));
            assert!(!row.contains(&identity.private_key));
        }
    })
    .catch_unwind()
    .await;
    drop(restore);
    runtime.stop().await.unwrap();
    drop(services);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}
