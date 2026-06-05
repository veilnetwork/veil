//! decomposition PR2: mailbox-domain state
//! extracted into а dedicated [`Arc<MailboxState>`].
//!
//! ## Why а dedicated struct
//!
//! Pre-PR2, `NodeRuntime` held two mailbox-domain fields directly
//! (`mailbox: Option<Arc<Mailbox>>`, `outbox: Option<Arc<Outbox>>`)
//! sprinkled с DHT / session / anonymity state. Both are
//! Optional-Arc handles populated at startup based on operator config
//! и never reassigned at runtime — so а dedicated struct doesn't add
//! mutex bookkeeping, но it does:
//!
//! 1. Gives slice-3 follow-ups а natural home (per-sender quota
//!    counters, capability-token enforcement state, push dispatcher
//!    references, eventually mailbox-replication coordinator).
//! 2. Keeps `NodeRuntime` reads against а typed domain bundle —
//!    `self.mailbox_state.mailbox` / `.outbox` instead of two siblings
//!    that need к be mentally grouped.
//! 3. Mirrors the `AnonymityState` pattern shipped в PR1.
//!
//! ## Migration surface
//!
//! Each callsite reading `self.mailbox` / `self.outbox` now reads
//! `self.mailbox_state.mailbox` / `.outbox`. Builder collapses the
//! two `Option<Arc<...>>` builder vars into а single `MailboxState::new`
//! call. No behaviour change.

use std::sync::Arc;

use veil_mailbox::{Mailbox, Outbox};

/// Mailbox-domain state owned by [`crate::node::NodeRuntime`].
///
/// Both handles are populated at startup; `None` reflects operator
/// config (mailbox: only when `mailbox.enabled = true`; outbox: only
/// when `Outbox::open` succeeded — peer-sync is а universal feature
/// but disk failure can degrade it gracefully).
pub struct MailboxState {
    ///.4 P2: mailbox handle, populated
    /// only when `config.mailbox.enabled = true`. IPC `MailboxPut /
    /// Fetch / Ack` handlers route through this; `None` means the
    /// daemon refuses mailbox operations с `NotMailboxRelay` /
    /// empty list.
    pub mailbox: Option<Arc<Mailbox>>,

    ///.4 P4: sender-side outbox handle
    /// for peer-sync. Open whenever the daemon runs as anything that
    /// can send messages (i.e. always, not gated на `mailbox.enabled`).
    /// Stored at `<veil_dir>/mailbox/outbox.db`.
    pub outbox: Option<Arc<Outbox>>,
}

impl MailboxState {
    pub fn new(mailbox: Option<Arc<Mailbox>>, outbox: Option<Arc<Outbox>>) -> Self {
        Self { mailbox, outbox }
    }
}
