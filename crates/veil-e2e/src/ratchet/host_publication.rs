//! Process-local publication floors supplied only after a host commit.
use super::{ConversationKey, MAX_CONVERSATIONS, RatchetSpliceError, RatchetStore};
use std::collections::{BTreeMap, BTreeSet};
use veil_ratchet::SendPosition;

/// Current host attachment. Epoch zero is an unjournaled, memory-only store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostPublicationState {
    /// Attachment generation; a retired owner cannot authorize a new owner.
    pub epoch: u64,
    /// Whether this generation still accepts durable publication floors.
    pub active: bool,
    /// Conversations whose next encryption needs a durable floor.
    pub required: usize,
}

/// A host attempted to authorize a floor outside its current attachment.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HostPublicationError {
    /// Another host attachment superseded this one, or it was closed.
    #[error("host publication attachment is closed or superseded")]
    Inactive,
    /// The supplied key names no live conversation.
    #[error("host publication conversation is absent")]
    NoConversation,
    /// A floor is farther ahead than legitimate recovery can burn.
    #[error("host publication floor exceeds the recovery bound")]
    TooFar,
}

#[derive(Default)]
pub(super) struct HostPublication {
    pub(super) epoch: u64,
    active: bool,
    floors: BTreeMap<ConversationKey, Vec<SendPosition>>,
    required: BTreeSet<ConversationKey>,
}

impl HostPublication {
    pub(super) fn prune_at_capacity(&mut self, live: impl Fn(&ConversationKey) -> bool) {
        if self.required.len() >= MAX_CONVERSATIONS {
            self.required.retain(|key| live(key));
        }
    }
    pub(super) fn check(
        &mut self,
        key: ConversationKey,
        position: Option<SendPosition>,
    ) -> Result<(), RatchetSpliceError> {
        if self.epoch == 0 {
            return Ok(());
        }
        if !self.active {
            return Err(RatchetSpliceError::HostPublicationClosed);
        }
        let Some(at) = position else {
            return Ok(());
        };
        if self.floors.get(&key).is_some_and(|marks| {
            marks
                .iter()
                .any(|m| m.chain == at.chain && at.next < m.next)
        }) {
            return Ok(());
        }
        // Keys are live entries, bounded by MAX_CONVERSATIONS. Stale entries
        // are removed by the host-state query before more floors are installed.
        if self.required.len() < MAX_CONVERSATIONS {
            self.required.insert(key);
        }
        Err(RatchetSpliceError::HostReservationRequired)
    }

    pub(super) fn first_seal(&mut self, key: ConversationKey) -> Result<(), RatchetSpliceError> {
        if self.epoch == 0 {
            return Ok(());
        }
        if !self.active {
            return Err(RatchetSpliceError::HostPublicationClosed);
        }
        if self.required.len() < MAX_CONVERSATIONS {
            self.required.insert(key);
        }
        // PQXDH creates the entry and its first ciphertext atomically. Keep
        // the new state dirty, but discard that unpublished ciphertext. The
        // original request retries after its new chain has a durable floor;
        // the retained prologue already supports loss of the first frame.
        Err(RatchetSpliceError::HostReservationRequired)
    }
}

impl RatchetStore {
    /// Attach a journaling host before its application begins sending.
    /// All later ratchet encryptions require a host-committed floor, including
    /// encryptions performed by delayed IPC commands and newly created chains.
    pub fn begin_host_publication(&self) -> u64 {
        let mut g = self.lock();
        let gate = &mut g.host_publication;
        gate.epoch = gate.epoch.wrapping_add(1).max(1);
        gate.active = true;
        gate.floors.clear();
        gate.required.clear();
        gate.epoch
    }

    /// Read bounded reservation demand; never writes or advances crypto state.
    pub fn host_publication_state(&self) -> HostPublicationState {
        let mut g = self.lock();
        let super::Inner {
            entries,
            host_publication: gate,
            ..
        } = &mut *g;
        gate.floors.retain(|key, _| entries.contains_key(key));
        gate.required.retain(|key| entries.contains_key(key));
        HostPublicationState {
            epoch: gate.epoch,
            active: gate.active,
            required: gate.required.len(),
        }
    }

    /// Read a request's wait state without copying plaintext or consuming a
    /// key on every retry. The final check inside `seal` remains authoritative.
    pub fn host_publication_pending(
        &self,
        epoch: u64,
        key: &ConversationKey,
    ) -> Result<bool, HostPublicationError> {
        let g = self.lock();
        if g.host_publication.epoch != epoch || (epoch != 0 && !g.host_publication.active) {
            return Err(HostPublicationError::Inactive);
        }
        Ok(g.host_publication.required.contains(key))
    }

    /// Permit positions only AFTER their reservation is durably committed by
    /// the owner. Public key/counter metadata is not proof of a disk commit;
    /// this is a trusted host API, never a peer-controlled protocol message.
    pub fn allow_host_publication(
        &self,
        epoch: u64,
        key: &ConversationKey,
        marks: &[SendPosition],
    ) -> Result<(), HostPublicationError> {
        let mut g = self.lock();
        if !g.host_publication.active || g.host_publication.epoch != epoch {
            return Err(HostPublicationError::Inactive);
        }
        let live = g
            .entries
            .get(key)
            .ok_or(HostPublicationError::NoConversation)?
            .send_positions();
        for mark in marks {
            if let Some(at) = live.iter().find(|at| at.chain == mark.chain)
                && mark.next > at.next.saturating_add(veil_ratchet::MAX_SEND_SKIP)
            {
                return Err(HostPublicationError::TooFar);
            }
        }
        let super::Inner {
            entries,
            host_publication: gate,
            ..
        } = &mut *g;
        gate.floors.retain(|k, _| entries.contains_key(k));
        let allowed = gate.floors.entry(*key).or_default();
        allowed.retain(|m| live.iter().any(|at| at.chain == m.chain));
        for mark in marks {
            if !live.iter().any(|at| at.chain == mark.chain) {
                continue;
            }
            if let Some(old) = allowed.iter_mut().find(|old| old.chain == mark.chain) {
                old.next = old.next.max(mark.next);
            } else {
                allowed.push(*mark);
            }
        }
        if live.iter().all(|at| {
            allowed
                .iter()
                .any(|m| m.chain == at.chain && at.next < m.next)
        }) {
            gate.required.remove(key);
        }
        Ok(())
    }

    /// Retire this host attachment without releasing blocked ciphertexts.
    /// A later attachment has a fresh epoch and cannot be closed by this one.
    pub fn end_host_publication(&self, epoch: u64) {
        let mut g = self.lock();
        if g.host_publication.epoch == epoch {
            g.host_publication.active = false;
            g.host_publication.floors.clear();
            g.host_publication.required.clear();
        }
    }
}
