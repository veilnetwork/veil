//! Mutual binding of a generic auxiliary transport to a live session.
//!
//! SessionRunner authenticates exactly once per connection, bounds sibling
//! slots, and retires the owner on close/rekey/replacement. It must not install
//! a sibling in the canonical peer registry or advertise it as another node.
//! No audio/video role or scheduling request occurs in either proof.

use rand::RngCore;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub(crate) const PREFACE: &[u8; 8] = b"VPAUX001";
pub const HELLO_BYTES: usize = 104;

struct Parent {
    session_id: [u8; 32],
    tx: Zeroizing<[u8; 32]>,
    rx: Zeroizing<[u8; 32]>,
    active: AtomicBool,
}

/// Owns credentials copied from an authenticated canonical session. Dropping
/// this owner retires all cloned handles and pending proofs automatically.
/// The canonical session must keep this owner, never an auxiliary task.
pub struct ParallelParent {
    handle: ParallelParentHandle,
}

impl std::ops::Deref for ParallelParent {
    type Target = ParallelParentHandle;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl Drop for ParallelParent {
    fn drop(&mut self) {
        self.handle.retire();
    }
}

/// A borrowed lifetime in owned form: cloning this handle keeps key storage
/// alive, but cannot prolong the canonical owner's authorization.
#[derive(Clone)]
pub struct ParallelParentHandle(Arc<Parent>);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BindingError {
    #[error("parallel channel parent retired")]
    Retired,
    #[error("invalid parallel channel proof")]
    InvalidProof,
}

/// Independently derived keys: sequence zero is safe on this child, rather
/// than reusing the parent's key/nonce space. Debug never prints key material.
pub struct ParallelKeys {
    pub session_id: [u8; 32],
    tx: Zeroizing<[u8; 32]>,
    rx: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for ParallelKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParallelKeys")
            .field("keys", &"<redacted>")
            .finish()
    }
}

impl ParallelKeys {
    pub fn tx_key(&self) -> &[u8; 32] {
        &self.tx
    }
    pub fn rx_key(&self) -> &[u8; 32] {
        &self.rx
    }
}

/// An outgoing proof, consumed when the remote acknowledgement is verified.
/// Retains zeroized exporter material only until that verification finishes.
pub struct PendingParallelBinding {
    parent: ParallelParentHandle,
    nonce: [u8; 32],
    exporter: Zeroizing<[u8; 32]>,
}

fn proof(
    key: &[u8; 32],
    domain: &[u8],
    sid: &[u8; 32],
    nonce: &[u8; 32],
    exporter: &[u8; 32],
) -> [u8; 32] {
    let mut hash = blake3::Hasher::new_keyed(key);
    hash.update(domain);
    hash.update(sid);
    hash.update(nonce);
    hash.update(exporter);
    *hash.finalize().as_bytes()
}

impl ParallelParent {
    /// An auxiliary task may retain this handle without owning the canonical
    /// session's lifetime. Dropping the owner still invalidates the handle.
    pub fn handle(&self) -> ParallelParentHandle {
        self.handle.clone()
    }

    /// The session owner must call `retire` before replacing these credentials.
    /// Transport security alone does not establish an OVL1 identity; do not source these keys
    /// or the session ID from an unverified peer-supplied preface.
    pub fn new(session_id: [u8; 32], tx: [u8; 32], rx: [u8; 32]) -> Self {
        Self {
            handle: ParallelParentHandle(Arc::new(Parent {
                session_id,
                tx: Zeroizing::new(tx),
                rx: Zeroizing::new(rx),
                active: AtomicBool::new(true),
            })),
        }
    }
}

impl ParallelParentHandle {
    pub(crate) fn is_active(&self) -> bool {
        self.0.active.load(Ordering::Acquire)
    }
    pub fn retire(&self) {
        self.0.active.store(false, Ordering::Release);
    }

    fn check_active(&self) -> Result<(), BindingError> {
        if self.0.active.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(BindingError::Retired)
        }
    }

    /// Use the new QUIC connection's exporter, never the parent's exporter.
    pub fn begin(
        &self,
        exporter: [u8; 32],
    ) -> Result<([u8; HELLO_BYTES], PendingParallelBinding), BindingError> {
        let exporter = Zeroizing::new(exporter);
        self.check_active()?;
        let mut nonce = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let mut hello = [0; HELLO_BYTES];
        hello[..8].copy_from_slice(PREFACE);
        hello[8..40].copy_from_slice(&self.0.session_id);
        hello[40..72].copy_from_slice(&nonce);
        hello[72..].copy_from_slice(&proof(
            &self.0.tx,
            b"veil/parallel/hello/v1",
            &self.0.session_id,
            &nonce,
            &exporter,
        ));
        Ok((
            hello,
            PendingParallelBinding {
                parent: self.clone(),
                nonce,
                exporter,
            },
        ))
    }

    /// Verify before interpreting any child frames. Call once per newly
    /// accepted QUIC connection, using its exporter. A captured preface cannot
    /// authenticate a different TLS connection, even to the same UDP endpoint.
    pub fn accept(
        &self,
        hello: &[u8; HELLO_BYTES],
        exporter: [u8; 32],
    ) -> Result<([u8; 32], ParallelKeys), BindingError> {
        let exporter = Zeroizing::new(exporter);
        self.check_active()?;
        if &hello[..8] != PREFACE || hello[8..40] != self.0.session_id {
            return Err(BindingError::InvalidProof);
        }
        let nonce: [u8; 32] = hello[40..72].try_into().expect("fixed preface");
        let expected = proof(
            &self.0.rx,
            b"veil/parallel/hello/v1",
            &self.0.session_id,
            &nonce,
            &exporter,
        );
        if !bool::from(expected.ct_eq(&hello[72..])) {
            return Err(BindingError::InvalidProof);
        }
        self.check_active()?;
        let ack = proof(
            &self.0.tx,
            b"veil/parallel/ack/v1",
            &self.0.session_id,
            &nonce,
            &exporter,
        );
        Ok((ack, self.keys(&nonce, &exporter)))
    }

    fn keys(&self, nonce: &[u8; 32], exporter: &[u8; 32]) -> ParallelKeys {
        // Child identity is opaque; it carries no traffic class or priority.
        let mut id = blake3::Hasher::new_derive_key("veil/parallel/session-id/v1");
        id.update(&self.0.session_id);
        id.update(nonce);
        id.update(exporter);
        ParallelKeys {
            session_id: *id.finalize().as_bytes(),
            tx: Zeroizing::new(proof(
                &self.0.tx,
                b"veil/parallel/key/v1",
                &self.0.session_id,
                nonce,
                exporter,
            )),
            rx: Zeroizing::new(proof(
                &self.0.rx,
                b"veil/parallel/key/v1",
                &self.0.session_id,
                nonce,
                exporter,
            )),
        }
    }
}

impl PendingParallelBinding {
    pub fn finish(self, ack: &[u8; 32]) -> Result<ParallelKeys, BindingError> {
        self.parent.check_active()?;
        let expected = proof(
            &self.parent.0.rx,
            b"veil/parallel/ack/v1",
            &self.parent.0.session_id,
            &self.nonce,
            &self.exporter,
        );
        if !bool::from(expected.ct_eq(ack)) {
            return Err(BindingError::InvalidProof);
        }
        self.parent.check_active()?;
        Ok(self.parent.keys(&self.nonce, &self.exporter))
    }
}

#[cfg(test)]
#[path = "parallel_binding_tests.rs"]
mod tests;
