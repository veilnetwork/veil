//! Keys that expire, and the two timers that replace them.
//!
//! Both tasks answer the same question — what happens to a key when its
//! window ends — and they answer it the same way, which is why they belong
//! together rather than next to whatever happened to be adjacent:
//!
//!  * [`NodeRuntime::spawn_mlkem_rotation_task`] rotates the long-term
//!    ML-KEM mailbox key, keeping the outgoing one decrypt-capable for its
//!    overlap so mail already in flight still opens.
//!  * [`NodeRuntime::spawn_ticket_key_rotation_task`] does the same for
//!    session-resumption ticket keys.
//!
//! The shared discipline is the one worth not losing: both POLL the epoch
//! rather than counting intervals. A phone suspends and a laptop sleeps, so
//! a timer that assumes it fired on schedule drifts out of step with the key
//! a restart would derive; comparing the current epoch against the ring's is
//! correct across any gap. Writing a third rotation task by copying whatever
//! is nearest is how that property gets lost, and putting the two that have
//! it in one file is the cheapest way to make the pattern visible.
//!
//! Moved verbatim out of `service_tasks.rs` (report24 RUNTIME-3). Behaviour
//! is unchanged; these are the same inherent methods on the same type.

use std::sync::Arc;

use super::{NodeRuntime, lock_tasks, supervised_spawn};

impl NodeRuntime {
    /// Replace the node's long-term ML-KEM mailbox key once per configured
    /// interval, keeping the outgoing one decrypt-capable for its overlap.
    ///
    /// Three ways this declines to run, all logged rather than silent:
    ///
    /// * `mlkem_rotation_secs == 0` — the operator turned it off.
    /// * the interval is under [`veil_e2e::MLKEM_SEED_MIN_OVERLAP_SECS`] — see
    ///   that constant for why the floor is over a week. Refused, not clamped:
    ///   a value that low means the caller is modelling this as a session key.
    /// * this node's key is not derivable (a persisted `mlkem.key`), so there is
    ///   no epoch sequence to walk.
    ///
    /// The tick POLLS the epoch rather than counting intervals. A phone
    /// suspends, a laptop sleeps, and a timer that assumes it fired on schedule
    /// would drift out of step with the key a restart would derive. Comparing
    /// `rotation_epoch(now)` against the ring's epoch is correct across any gap.
    pub fn spawn_mlkem_rotation_task(&mut self, config: &veil_cfg::Config) {
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let rotation_secs = config.global.mlkem_rotation_secs;
        let logger = Arc::clone(&self.logger);
        if rotation_secs == 0 {
            logger.info(
                "node.mlkem_dk.rotation_disabled",
                "mlkem_rotation_secs=0 — the mailbox key is never replaced, so a leak of it \
                 stays retroactive over the node's whole history",
            );
            return;
        }
        if rotation_secs < veil_e2e::MLKEM_SEED_MIN_OVERLAP_SECS {
            logger.warn(
                "node.mlkem_dk.rotation_interval_too_short",
                format!(
                    "mlkem_rotation_secs={rotation_secs} is under the {}s a sealed mailbox blob \
                     can outlive a rotation — refusing to rotate rather than dropping mail",
                    veil_e2e::MLKEM_SEED_MIN_OVERLAP_SECS,
                ),
            );
            return;
        }
        let veil_dir = self.identity_dir.clone();
        let mlkem_key_path = veil_dir.join("mlkem.key");
        if crate::identity_local::mlkem_dk::derive_for_epoch(&mlkem_key_path, &veil_dir, 0)
            .is_none()
        {
            logger.info(
                "node.mlkem_dk.rotation_unavailable",
                "this node's mailbox key is not derived from its identity (persisted or \
                 identity-less), so it has no epoch sequence to rotate along",
            );
            return;
        }

        let mut shutdown_rx = shutdown_tx.subscribe();
        let mlkem_keys = Arc::clone(&self.identity.mlkem_keys);
        let republish_now = Arc::clone(&self.mlkem_republish_now);
        let handle = supervised_spawn(Arc::clone(&self.logger), "mlkem_key_rotation", async move {
            // Poll far more often than the interval: the cost is an integer
            // division, and it bounds how long a resumed-from-suspend node
            // publishes a key its own clock says is stale.
            const POLL: std::time::Duration = std::time::Duration::from_secs(60);
            let mut interval = tokio::time::interval(POLL);
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        let want = crate::identity_local::mlkem_dk::rotation_epoch(
                            now,
                            rotation_secs,
                        );
                        if want <= mlkem_keys.epoch() {
                            // Also the first tick, which fires immediately:
                            // startup already derived this epoch's key.
                            mlkem_keys.prune(now);
                            continue;
                        }
                        let Some((ek, dk)) = crate::identity_local::mlkem_dk::derive_for_epoch(
                            &mlkem_key_path,
                            &veil_dir,
                            want,
                        ) else {
                            // The identity file went away mid-session (an
                            // identity switch, a wiped runtime dir). Keep the
                            // current key rather than inventing one.
                            logger.warn(
                                "node.mlkem_dk.rotation_derive_failed",
                                format!("could not derive the epoch-{want} mailbox key — \
                                         keeping the current one"),
                            );
                            continue;
                        };
                        match Self::rotate_and_announce(
                            &mlkem_keys,
                            &republish_now,
                            now,
                            want,
                            dk,
                            ek,
                            rotation_secs,
                        ) {
                            Ok(()) => logger.info(
                                "node.mlkem_dk.rotated",
                                format!(
                                    "mailbox key now at epoch {want}; the previous one \
                                     stays decrypt-capable for {rotation_secs}s so mail \
                                     already sealed to it still opens",
                                ),
                            ),
                            Err(e) => logger.warn(
                                "node.mlkem_dk.rotation_refused",
                                format!("seed ring refused the rotation: {e}"),
                            ),
                        }
                    }
                    Ok(_) = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });
        lock_tasks(&self.tasks).background.push(handle);
    }

    /// Spawn the ticket-key rotation task.
    ///
    /// The host ticket key used to be generated once at startup and kept for
    /// the process lifetime, so a host compromised weeks into a run yielded a
    /// key that decrypts every session ticket the process ever issued. Every
    /// `TICKET_KEY_ROTATION_SECS` the issuer moves to a fresh key and keeps the
    /// outgoing one as decrypt-only for one further interval — long enough for
    /// tickets minted just before the swap to live out their TTL, which is why
    /// the interval is pinned at or above `SESSION_TICKET_TTL_SECS`.
    pub fn spawn_ticket_key_rotation_task(&mut self) {
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let mut shutdown_rx = shutdown_tx.subscribe();
        let issuer = Arc::clone(&self.resumption.ticket_issuer);
        let logger = Arc::clone(&self.logger);
        let handle = supervised_spawn(
            Arc::clone(&self.logger),
            "ticket_key_rotation",
            async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(
                    veil_session::ticket::TICKET_KEY_ROTATION_SECS,
                ));
                // The first tick fires immediately and the startup key is
                // already fresh; rotating here would throw away a key nothing
                // has used yet and open an overlap window for no reason.
                interval.tick().await;
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            match issuer.lock() {
                                Ok(mut g) => g.rotate_fresh(),
                                Err(p) => p.into_inner().rotate_fresh(),
                            }
                            logger.info(
                                "ticket.key.rotated",
                                format!(
                                    "new host ticket key; previous kept for one more \
                                     {}s window so live tickets still resume",
                                    veil_session::ticket::TICKET_KEY_ROTATION_SECS,
                                ),
                            );
                        }
                        Ok(_) = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() {
                                break;
                            }
                        }
                    }
                }
            },
        );
        lock_tasks(&self.tasks).background.push(handle);
    }
}
