//! Built-in app service host.
//!
//! See `super` module docs for the design rationale.

use std::future::Future;
use std::sync::Arc;

use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use veil_app::{AppEndpointRegistry, AppMessage, EndpointHandle};

/// One endpoint a service binds at startup. The `capacity` is the
/// underlying mpsc channel buffer — pick a value high enough to
/// absorb bursts without blocking the dispatcher's incoming-frame
/// path, but bounded so a misbehaving peer cannot pin an unlimited
/// amount of memory.
#[derive(Debug, Clone, Copy)]
pub struct BuiltinEndpoint {
    /// Endpoint id (per-service convention; e.g. mailbox uses 1/2/3).
    pub endpoint_id: u32,
    /// mpsc channel buffer depth.
    pub capacity: usize,
}

/// Static description of a built-in app service. Passed to
/// [`BuiltinAppHost::spawn`]. The `app_id` is the well-known 32-byte
/// constant the service binds; remote peers (and IPC clients) target
/// this id when sending to the service.
#[derive(Debug, Clone)]
pub struct ServiceSpec {
    /// Human-readable name for logs / metrics (e.g. "veil-mailbox").
    pub name: &'static str,
    /// 32-byte well-known app id (typically a hash of a name string).
    pub app_id: [u8; 32],
    /// Endpoints to bind on startup. All bound atomically — a
    /// failure to bind any one aborts the spawn. Empty vector is
    /// allowed (degenerate case useful for tests).
    pub endpoints: Vec<BuiltinEndpoint>,
}

/// Per-service runtime context passed to the service closure.
///
/// Carries the shared dependencies the service needs (registry for
/// future re-binds, local node identity, shutdown signal) without
/// dragging in the full `NodeRuntime` graph.
#[derive(Clone)]
pub struct ServiceContext {
    /// Local node id (for self-addressed messages, log lines, etc.).
    pub local_node_id: [u8; 32],
    /// Shared app-endpoint registry — the service holds endpoint
    /// handles by storing them on its task; these handles live as
    /// long as the spawned task.
    pub app_registry: Arc<AppEndpointRegistry>,
    /// Watch channel that fires once when the host calls [`BuiltinAppHost::shutdown`].
    /// Service closures should `tokio::select!` on this alongside
    /// their endpoint receivers and exit cleanly when it fires.
    pub shutdown: watch::Receiver<bool>,
}

/// Owner of all currently-registered built-in services. Cheap to
/// construct (no allocations until first `spawn`).
pub struct BuiltinAppHost {
    /// Task handles for spawned services.
    tasks: Vec<JoinHandle<()>>,
    /// RAII guards: each `EndpointHandle::drop` deregisters its
    /// endpoint from the host registry. The field is never read by
    /// name — it exists purely for its Drop side-effect when the host
    /// is torn down (or replaced). Do NOT remove the
    /// `#[allow(dead_code)]`: a future refactor that drops this field
    /// "because nothing reads it" would silently leak endpoint
    /// registrations across host lifecycles.
    #[allow(dead_code)]
    endpoint_handles: Vec<EndpointHandle>,
    /// Shutdown signal sender. When the host is dropped (or
    /// `shutdown` is called), this transitions to `true` and every
    /// service's `ctx.shutdown` watch receiver fires.
    shutdown_tx: watch::Sender<bool>,
}

impl BuiltinAppHost {
    /// Construct an empty host. No tasks are spawned until [`Self::spawn`]
    /// is called.
    pub fn new() -> Self {
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);
        Self {
            tasks: Vec::new(),
            endpoint_handles: Vec::new(),
            shutdown_tx,
        }
    }

    /// Build a `ServiceContext` for use by a freshly-spawned service.
    /// Cloning is cheap (Arc + watch receiver).
    pub fn make_context(
        &self,
        local_node_id: [u8; 32],
        app_registry: Arc<AppEndpointRegistry>,
    ) -> ServiceContext {
        ServiceContext {
            local_node_id,
            app_registry,
            shutdown: self.shutdown_tx.subscribe(),
        }
    }

    /// Register a service's endpoints and spawn its task.
    ///
    /// `run` is invoked exactly once with:
    /// 1. The cloned `ServiceContext`
    /// 2. A vector of mpsc receivers, one per declared endpoint, in
    ///    the same order as `spec.endpoints`.
    ///
    /// The service should `tokio::select!` between these receivers
    /// and `ctx.shutdown.changed`. Returning from `run` is
    /// equivalent to graceful exit.
    ///
    /// Panics in the spawned task are caught by tokio and surfaced
    /// as `JoinError` when [`Self::shutdown`] joins the handle; the
    /// caller is expected to log and not propagate the panic.
    pub fn spawn<F, Fut>(&mut self, ctx: ServiceContext, spec: ServiceSpec, run: F)
    where
        F: FnOnce(ServiceContext, Vec<mpsc::Receiver<AppMessage>>) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let mut receivers = Vec::with_capacity(spec.endpoints.len());
        for ep in &spec.endpoints {
            let (handle, rx) = ctx
                .app_registry
                .register(spec.app_id, ep.endpoint_id, ep.capacity);
            self.endpoint_handles.push(handle);
            receivers.push(rx);
        }
        log::info!(
            "builtin-app: spawned {name} on app_id={hex} ({n} endpoints)",
            name = spec.name,
            hex = bytes_to_hex_short(&spec.app_id),
            n = spec.endpoints.len(),
        );
        let task = tokio::spawn(async move {
            run(ctx, receivers).await;
        });
        self.tasks.push(task);
    }

    /// Signal every service to stop and await its task.
    ///
    /// Returns once all tasks have either exited cleanly or been
    /// aborted by their own panic. Best-effort — tasks that
    /// genuinely hang (don't honour the shutdown watch) are aborted
    /// after a short grace period.
    pub async fn shutdown(mut self) {
        let _ = self.shutdown_tx.send(true);
        // Drop endpoint handles eagerly so any in-flight `register`
        // races fail fast; the tasks will see their receivers close
        // and exit. `mem::take` so the `Drop` impl that follows
        // doesn't double-handle them.
        drop(std::mem::take(&mut self.endpoint_handles));
        // Tokio's JoinHandle::await never panics — it returns
        // JoinError if the task panicked, which we log and discard.
        let tasks = std::mem::take(&mut self.tasks);
        for h in tasks {
            match tokio::time::timeout(std::time::Duration::from_secs(2), h).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) if e.is_panic() => {
                    log::warn!("builtin-app: service panicked during shutdown: {e}");
                }
                Ok(Err(e)) => {
                    log::warn!("builtin-app: service join error: {e}");
                }
                Err(_) => {
                    log::warn!("builtin-app: service did not exit within 2s — aborting");
                    // Timeout dropped the JoinHandle; tokio aborts
                    // the task on drop.
                }
            }
        }
        // `self` falls through to its Drop impl, which fires shutdown
        // again on (already-fired) watch channel — harmless — and
        // iterates the now-empty `tasks` vec.
    }

    /// Number of currently-running services. For metrics / tests.
    pub fn task_count(&self) -> usize {
        self.tasks.len()
    }
}

impl Default for BuiltinAppHost {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for BuiltinAppHost {
    /// Best-effort cleanup when the host is dropped without an explicit
    /// `shutdown.await`. Fires the shutdown watch и aborts every
    /// outstanding task. Necessary for the NodeRuntime path где stop
    /// runs in a sync `Drop` context (e.g. on panic-unwind) — async
    /// shutdown is unavailable, abort is the only fallback. Tasks
    /// that registered on `ctx.shutdown` may have already exited
    /// cleanly; for those `abort` is a no-op.
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        for h in &self.tasks {
            h.abort();
        }
    }
}

/// First 8 hex chars — enough to identify a service in logs without
/// dumping a full app_id on every line.
pub fn bytes_to_hex_short(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(16);
    for x in b.iter().take(8) {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;

    fn fresh() -> (BuiltinAppHost, Arc<AppEndpointRegistry>) {
        (BuiltinAppHost::new(), Arc::new(AppEndpointRegistry::new()))
    }

    #[tokio::test]
    async fn t1_4_p5a_spawn_and_shutdown_clean() {
        let (mut host, reg) = fresh();
        let ctx = host.make_context([0u8; 32], Arc::clone(&reg));
        host.spawn(
            ctx,
            ServiceSpec {
                name: "test",
                app_id: [1u8; 32],
                endpoints: vec![BuiltinEndpoint {
                    endpoint_id: 1,
                    capacity: 4,
                }],
            },
            |mut ctx, rxs| async move {
                // Park on shutdown — exit when host signals.
                let _ = ctx.shutdown.changed().await;
                drop(rxs);
            },
        );
        assert_eq!(host.task_count(), 1);
        host.shutdown().await;
    }

    #[tokio::test]
    async fn t1_4_p5a_endpoints_bound_after_spawn() {
        // Verify that after `spawn`, sending to the registered endpoint
        // actually delivers to the service's receiver.
        let (mut host, reg) = fresh();
        let app_id = [7u8; 32];
        let ctx = host.make_context([0u8; 32], Arc::clone(&reg));

        // Channel the test uses to peek at what the service received.
        let (peek_tx, peek_rx) = oneshot::channel::<Vec<u8>>();

        host.spawn(
            ctx,
            ServiceSpec {
                name: "echo-test",
                app_id,
                endpoints: vec![BuiltinEndpoint {
                    endpoint_id: 42,
                    capacity: 4,
                }],
            },
            move |mut ctx, mut rxs| async move {
                let mut rx = rxs.remove(0);
                tokio::select! {
                    Some(msg) = rx.recv() => {
                        if let AppMessage::Deliver { data, .. } = msg {
                            let _ = peek_tx.send((*data).to_vec());
                        }
                    }
                    _ = ctx.shutdown.changed() => {}
                }
            },
        );

        // Inject a Deliver via the registry's `get_sender` API
        // (we can't construct a session-level frame in a unit test).
        let sender = reg.get_sender(app_id, 42).expect("endpoint registered");
        sender
            .try_send(AppMessage::Deliver {
                src_node_id: [9u8; 32],
                src_app_id: [0u8; 32],
                app_id,
                endpoint_id: 42,
                data: veil_bufpool::pooled_shared_from_vec(b"hello-builtin".to_vec()),
            })
            .expect("send to registered endpoint");

        let received = tokio::time::timeout(std::time::Duration::from_secs(1), peek_rx)
            .await
            .expect("recv timeout")
            .expect("oneshot");
        assert_eq!(received, b"hello-builtin");

        host.shutdown().await;
    }

    #[tokio::test]
    async fn t1_4_p5a_multiple_services_independent() {
        let (mut host, reg) = fresh();
        let ctx_a = host.make_context([0u8; 32], Arc::clone(&reg));
        let ctx_b = host.make_context([0u8; 32], Arc::clone(&reg));
        host.spawn(
            ctx_a,
            ServiceSpec {
                name: "a",
                app_id: [1u8; 32],
                endpoints: vec![BuiltinEndpoint {
                    endpoint_id: 1,
                    capacity: 4,
                }],
            },
            |mut ctx, _rxs| async move {
                let _ = ctx.shutdown.changed().await;
            },
        );
        host.spawn(
            ctx_b,
            ServiceSpec {
                name: "b",
                app_id: [2u8; 32],
                endpoints: vec![BuiltinEndpoint {
                    endpoint_id: 1,
                    capacity: 4,
                }],
            },
            |mut ctx, _rxs| async move {
                let _ = ctx.shutdown.changed().await;
            },
        );
        assert_eq!(host.task_count(), 2);
        host.shutdown().await;
    }

    #[tokio::test]
    async fn t1_4_p5a_shutdown_aborts_hung_service() {
        let (mut host, reg) = fresh();
        let ctx = host.make_context([0u8; 32], Arc::clone(&reg));
        host.spawn(
            ctx,
            ServiceSpec {
                name: "hung",
                app_id: [3u8; 32],
                endpoints: vec![],
            },
            |_ctx, _rxs| async move {
                // Ignore shutdown signal — sleep forever. Host should
                // abort us via 2s timeout.
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            },
        );
        let start = std::time::Instant::now();
        host.shutdown().await;
        // Should return within ~2s grace + a little slack, NOT 3600s.
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
    }

    #[tokio::test]
    async fn t1_4_p5a_default_constructs_empty_host() {
        let host = BuiltinAppHost::default();
        assert_eq!(host.task_count(), 0);
        host.shutdown().await;
    }
}
