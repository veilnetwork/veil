//! Production `BindClosure` для the PoW-Gated Rendezvous controller —
//! Slice 5c of the epic ([`docs/internal/PLAN_POW_GATED_RENDEZVOUS.md`]).
//!
//! Replaces the stub binder shipped в Slice 5b (which always returned
//! `BindFailed`) с the real wiring що:
//!
//! 1. Clones the base [`TransportContext`] и sets `obfs4_psk` к the
//!    per-request PSK so the obfs4-tcp listener handshakes against
//!    the requester's expected secret.
//! 2. Calls `TransportRegistry::bind(uri, ctx).await` к get the
//!    actual `Box<dyn TransportListener>`.
//! 3. Spawns а dedicated short-lived accept task that mirrors the
//!    Phase 5f accept-loop pattern (scanner-shield ban check, per-
//!    spawn inbound-handshake semaphore, full `spawn_inbound_session`
//!    pipeline) but bounded by [`OnDemandLifecycle`] (TTL deadline +
//!    accept-budget).
//!
//! When the accept task exits — TTL reached OR all `max_accepts`
//! sessions accepted OR shutdown signalled — the `Box<dyn
//! TransportListener>` drops, freeing the port back к the kernel.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::Semaphore;

use veil_transport::on_demand::OnDemandLifecycle;

use crate::listener_supervisor::{AcceptWaiters, pop_accept_waiter};
use crate::types::{ListenId, ListenerHandle};
use veil_session::rendezvous::BindClosure;
use veil_transport::{TransportContext, TransportListener, TransportRegistry, TransportUri};

use super::{
    InboundSessionContext, RuntimeTasks, SessionRuntimeContext, push_session_handle,
    spawn_inbound_session,
};

// ── AcceptBundle — captured Arcs needed for spawn_inbound_session ───

/// Cloneable bundle of all `Arc`s + values needed к build а
/// [`SessionRuntimeContext`] и spawn an inbound session.  Construction
/// happens once в `wire_rendezvous_controller_for_listen`; each
/// accepted connection clones (cheap — all `Arc`s) и calls
/// [`spawn_inbound_session`].
#[derive(Clone)]
pub struct AcceptBundle {
    pub ctx: SessionRuntimeContext,
    pub listen_id: ListenId,
    pub listener_handle: ListenerHandle,
    pub inbound_sem: Arc<Semaphore>,
    pub pending_accepts: Arc<std::sync::Mutex<AcceptWaiters>>,
    pub tasks: Arc<std::sync::Mutex<RuntimeTasks>>,
}

// ── Binder ──────────────────────────────────────────────────────────

/// Production `BindClosure` implementation.  Captures the bundle of
/// Arcs needed к bind а listener + spawn its accept task.
pub struct RendezvousBinder {
    pub registry: Arc<TransportRegistry>,
    pub base_ctx: Arc<TransportContext>,
    pub accept: AcceptBundle,
}

impl BindClosure for RendezvousBinder {
    fn bind(
        &self,
        uri: String,
        psk: [u8; 32],
        lifecycle: Arc<OnDemandLifecycle>,
    ) -> Pin<Box<dyn Future<Output = std::result::Result<(), String>> + Send + 'static>> {
        let registry = Arc::clone(&self.registry);
        let mut ctx_clone: TransportContext = (*self.base_ctx).clone();
        ctx_clone.obfs4_psk = Some(Arc::new(psk));
        let ctx = Arc::new(ctx_clone);
        let accept_bundle = self.accept.clone();

        Box::pin(async move {
            let parsed = TransportUri::parse(&uri)
                .map_err(|e| format!("rendezvous binder: parse uri `{uri}`: {e}"))?;
            let listener = registry
                .bind(&parsed, ctx)
                .await
                .map_err(|e| format!("rendezvous binder: bind {uri}: {e}"))?;
            let local_addr = listener.local_addr();
            // Spawn the bounded accept task — owns the listener для
            // its lifetime, drops on exit.
            tokio::spawn(run_on_demand_accept_task(
                listener,
                lifecycle,
                accept_bundle,
                local_addr,
            ));
            Ok(())
        })
    }
}

// ── Bounded accept task ─────────────────────────────────────────────

/// Accept-loop wrapper bounded by [`OnDemandLifecycle`].  Mirrors the
/// Phase 5f accept-loop pattern в `services.rs::spawn_listeners` (scanner-
/// shield check + accept-waiter dispatch + inbound-handshake semaphore
/// + `spawn_inbound_session` pipeline) but exits cleanly on TTL OR
///   после `max_accepts` sessions accepted.
///
/// Per-accept flow:
/// 1. Check `lifecycle.should_exit()` up-front; bail if exhausted.
/// 2. `tokio::select!` between `listener.accept()` и
///    `lifecycle.await_ttl_or_shutdown()`.  Either resolves → break.
/// 3. On accept: scanner-shield ban check (drop if IP banned).
/// 4. Pop а pending-accept waiter если any (debug-CLI accept hooks).
/// 5. Try-acquire inbound-handshake semaphore permit; drop connection
///    if cap reached.
/// 6. Call [`spawn_inbound_session`] с а freshly-cloned
///    [`SessionRuntimeContext`].
/// 7. `lifecycle.note_accept()` — decrement budget; break если returns 1.
async fn run_on_demand_accept_task(
    listener: Box<dyn TransportListener>,
    lifecycle: Arc<OnDemandLifecycle>,
    bundle: AcceptBundle,
    local_addr: String,
) {
    let logger = Arc::clone(&bundle.ctx.logger);
    let listen_id = bundle.listen_id;
    let listener_handle = bundle.listener_handle;
    logger.info(
        "rendezvous.on_demand.listener.spawned",
        format!(
            "listen_id={listen_id} listener_handle={listener_handle} \
             local_addr={local_addr} ttl_remaining={:?}s accepts_remaining={}",
            lifecycle
                .expires_at()
                .saturating_duration_since(std::time::Instant::now())
                .as_secs(),
            lifecycle.accepts_remaining(),
        ),
    );

    let scanner_shield = Arc::clone(&bundle.ctx.scanner_shield);

    loop {
        if lifecycle.should_exit() {
            break;
        }
        tokio::select! {
            _ = lifecycle.await_ttl_or_shutdown() => {
                logger.info(
                    "rendezvous.on_demand.listener.ttl_or_shutdown",
                    format!("listen_id={listen_id}"),
                );
                break;
            }
            accepted = listener.accept() => match accepted {
                Ok(connection) => {
                    // Scanner-shield: drop а banned-IP connection
                    // without burning а note_accept.  Mirrors the
                    // Phase 5f accept-loop check.
                    let banned_ip = connection
                        .peer_meta()
                        .remote_addr
                        .map(|sa| sa.ip())
                        .filter(|ip| scanner_shield.is_banned(*ip));
                    if let Some(ip) = banned_ip {
                        logger.info(
                            "rendezvous.on_demand.scanner_dropped",
                            format!(
                                "listen_id={listen_id} remote_ip={ip}",
                            ),
                        );
                        drop(connection);
                        continue;
                    }
                    // Pop а pending-accept waiter if any (debug-CLI
                    // path; the waiter consumes the connection и
                    // we skip session-spawn).
                    let connection = if let Some(waiter) =
                        pop_accept_waiter(&bundle.pending_accepts, listen_id)
                    {
                        match waiter.send((listener_handle, connection)) {
                            Ok(()) => {
                                // The waiter consumed the conn —
                                // count it against the accept budget
                                // and bail if exhausted.
                                let prev = lifecycle.note_accept();
                                if prev <= 1 {
                                    break;
                                }
                                continue;
                            }
                            Err((_, connection)) => connection,
                        }
                    } else {
                        connection
                    };
                    // Reserve а note_accept slot up-front так и
                    // capacity-dropped connections still count
                    // against the budget (DoS-resistance: keep the
                    // lifecycle clock running even на dropped
                    // attempts).  Race-safe: returns prev count.
                    let prev = lifecycle.note_accept();
                    if prev == 0 {
                        // Budget exhausted between should_exit check
                        // и here — bail.
                        drop(connection);
                        break;
                    }

                    // Try-acquire inbound-handshake semaphore.
                    let permit = match Arc::clone(&bundle.inbound_sem).try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            logger.info(
                                "rendezvous.on_demand.capacity_dropped",
                                format!(
                                    "listen_id={listen_id} — in-flight handshake cap reached",
                                ),
                            );
                            drop(connection);
                            if prev <= 1 { break; }
                            continue;
                        }
                    };

                    // Spawn the session.  SessionRuntimeContext clone
                    // is cheap (all Arc clones inside).
                    let handle = spawn_inbound_session(
                        InboundSessionContext {
                            runtime: bundle.ctx.clone(),
                            listen_id,
                            listener_handle,
                        },
                        connection,
                    );
                    // Wrap the handle к keep the permit alive for the
                    // session's lifetime.  Same idiom as Phase 5f.
                    let wrapped = tokio::spawn(async move {
                        let _permit = permit;
                        let _ = handle.await;
                    });
                    push_session_handle(&bundle.tasks, wrapped);

                    if prev <= 1 {
                        // Last allowed accept — bail.
                        logger.info(
                            "rendezvous.on_demand.budget_exhausted",
                            format!("listen_id={listen_id} max_accepts reached"),
                        );
                        break;
                    }
                }
                Err(err) => {
                    logger.warn(
                        "rendezvous.on_demand.accept_error",
                        format!(
                            "listen_id={listen_id} error={err}",
                        ),
                    );
                    // Bail на persistent accept-error rather than spinning
                    // — the listener is likely в а bad state.
                    break;
                }
            }
        }
    }

    logger.info(
        "rendezvous.on_demand.listener.exited",
        format!(
            "listen_id={listen_id} listener_handle={listener_handle} accepts_remaining={}",
            lifecycle.accepts_remaining(),
        ),
    );
}

// Slice 5c's binder is unit-tested transitively через the existing
// rendezvous-controller test suite (Slice 3 uses а RecordingBinder
// that captures bind calls).  Live `registry.bind()` + accept-task
// integration tests require а full NodeRuntime fixture + а real
// session-handshake counterparty — shipped в Slice 8 (integration
// tests, see PLAN_POW_GATED_RENDEZVOUS.md).  Until then the cargo
// check + workspace test pass is the regression protection.
