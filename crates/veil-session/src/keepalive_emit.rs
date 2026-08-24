//! SessionRunner decomposition slice 24: keepalive emission + probe-ack
//! ledger.
//!
//! Bundles two related pieces:
//!
//! 1. [`build_keepalive_frame`] — pure-function frame builder
//!    (`Control / Keepalive` with zero-byte body).  Used inline on the
//!    keepalive-due tick.
//! 2. [`PendingKeepaliveProbe`] — Option<Instant> wrapper with
//!    **oldest-preserved** try_arm semantics: when a keepalive is
//!    emitted while a previous probe is still unacked, the existing
//!    timestamp is preserved so the probe-timeout measures the
//!    longest unacked window rather than the most recent.  Tied to
//!    Epic 459 stage (c.2.2) hot-standby TX-health detection.
//!
//! # Why extracted
//!
//! Pre-slice the keepalive emission lived inline in SessionRunner::run()
//! as 33 LoC of header construction + pq.push + side-effect log +
//! manual `Option::is_none` armé.  Awkward to unit-test (would require
//! spinning up a full session) and repeated `is_some()` / `is_none()`
//! checks across run() and compute_sleep_deadline().
//!
//! After: emission is a 3-line push, and `PendingKeepaliveProbe` provides
//! semantically-named methods (`try_arm` / `oldest` / `clear` /
//! `is_armed`) with 5 unit tests pinning the oldest-preserved invariant.

use rand_core::{OsRng, RngCore};

use veil_proto::{ControlMsg, codec::encode_header, family::FrameFamily, header::FrameHeader};

/// Body-length range for a keepalive, in bytes.
///
/// The body carries nothing — the receiver never reads it (see the
/// `ControlMsg::Keepalive` arm of the control dispatcher, which answers with an
/// ack and never touches the body). Its whole job is to stop the frame from
/// having ONE size.
///
/// A zero-body keepalive was exactly HEADER_SIZE bytes, forever, on a jittered
/// but otherwise steady cadence. Encryption hides the contents, not the length,
/// so that was a constant an on-path classifier could match without decrypting
/// anything — the same shape argument that made the fixed circuit cell a
/// liability. TLS-bucket padding would also blur it, but it is off by default
/// (it inflated bulk traffic ~2.5x); this pays the cost only on the one frame
/// that is otherwise a fingerprint, at a few tens of bytes per period.
pub const KEEPALIVE_PAD_MIN: usize = 1;
pub const KEEPALIVE_PAD_MAX: usize = 96;

/// Random padding body for a keepalive or its ack. Length AND contents are
/// drawn fresh each time; an ack draws independently of the keepalive that
/// prompted it, so the pair does not correlate by size either.
pub fn keepalive_pad_body() -> Vec<u8> {
    let span = (KEEPALIVE_PAD_MAX - KEEPALIVE_PAD_MIN + 1) as u32;
    let len = KEEPALIVE_PAD_MIN + (OsRng.next_u32() % span) as usize;
    let mut body = vec![0u8; len];
    OsRng.fill_bytes(&mut body);
    body
}

/// Build a `Control / Keepalive` frame ready to push to the priority queue.
/// The body is random padding the peer discards — see [`keepalive_pad_body`].
/// Idempotent: returns a fresh `Vec<u8>`, of a fresh length, on every call.
pub fn build_keepalive_frame() -> Vec<u8> {
    let body = keepalive_pad_body();
    let mut hdr = FrameHeader::new(FrameFamily::Control as u8, ControlMsg::Keepalive as u16);
    hdr.body_len = body.len() as u32;
    let mut frame = encode_header(&hdr).to_vec();
    frame.extend_from_slice(&body);
    frame
}

/// Ledger of an in-flight keepalive-ack expectation, tied to Epic 459
/// stage (c.2.2) hot-standby TX-health detection.
///
/// # Why oldest-preserved
///
/// The probe-timeout measures *how long we've been waiting for any
/// ack* — not "how long since the most recent keepalive."  Consider:
/// keepalive_interval = 1 s, keepalive_probe_timeout = 5 s.  Peer dies
/// silently at t=0.  Without the oldest-preserved invariant, at t=0 we
/// arm with probe_since=0, at t=1 a new keepalive overwrites
/// probe_since=1, etc.  At t=5 probe_since=5, `now - probe_since = 0`,
/// timeout never fires.  The TX-health trigger silently stays off
/// forever and the session sits dead.
///
/// With oldest-preserved: t=0 arms probe_since=0, t=1's keepalive sees
/// the existing probe_since and leaves it alone.  At t=5 the timeout
/// fires correctly.
#[derive(Debug, Default, Clone, Copy)]
pub struct PendingKeepaliveProbe {
    /// Timestamp of the OLDEST unacked keepalive.  `None` when no probe
    /// is outstanding (after a KeepaliveAck arrives).
    armed_at: Option<tokio::time::Instant>,
}

impl PendingKeepaliveProbe {
    /// Construct a new ledger in the "no pending probe" state.
    pub fn new() -> Self {
        Self { armed_at: None }
    }

    /// Arm the probe if no prior probe is already armed.  Returns
    /// **`true`** when the probe was already armed (the caller's
    /// keepalive frame piggybacks on an existing probe-timeout
    /// window); **`false`** when this is a fresh arm.  Surface
    /// matches the inline-code intent: `let was_pending_set =
    /// probe.try_arm(now);`.
    pub fn try_arm(&mut self, now: tokio::time::Instant) -> bool {
        let was_armed = self.armed_at.is_some();
        if !was_armed {
            self.armed_at = Some(now);
        }
        was_armed
    }

    /// Whether a probe is currently armed.  Cheap accessor — used by
    /// the debug-log "was_set" field and by [`Self::oldest`]'s caller
    /// when an `Option<Instant>` is a cleaner shape than a bool +
    /// follow-up read.
    pub fn is_armed(&self) -> bool {
        self.armed_at.is_some()
    }

    /// Timestamp of the oldest unacked keepalive, OR `None` if none
    /// is pending.  Used by:
    /// * `compute_sleep_deadline` to set the probe-timeout wake-up.
    /// * The probe-timeout check itself: `now - oldest >= probe_timeout`
    ///   fires the TX-health trigger.
    pub fn oldest(&self) -> Option<tokio::time::Instant> {
        self.armed_at
    }

    /// Clear the probe ledger.  Called when KeepaliveAck arrives —
    /// confirms the TX leg is live.
    pub fn clear(&mut self) {
        self.armed_at = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_proto::codec::decode_header;

    /// `build_keepalive_frame` must encode a valid Control/Keepalive frame
    /// whose declared body length matches the bytes actually appended. Wire
    /// shape is checked by decoding the result back through the same codec.
    #[test]
    fn build_frame_decodes_as_control_keepalive_with_its_body() {
        let frame = build_keepalive_frame();
        let hdr = decode_header(&frame).expect("decodes");
        assert_eq!(hdr.family, FrameFamily::Control as u8);
        assert_eq!(hdr.msg_type, ControlMsg::Keepalive as u16);
        assert_eq!(
            frame.len(),
            veil_proto::header::HEADER_SIZE + hdr.body_len as usize,
            "declared body length must match the bytes on the wire"
        );
        assert!(
            (KEEPALIVE_PAD_MIN..=KEEPALIVE_PAD_MAX).contains(&(hdr.body_len as usize)),
            "body {} outside the padding range",
            hdr.body_len
        );
    }

    /// A keepalive must not have ONE size. Drawing many frames must produce
    /// more than a single length — the property the padding exists for.
    ///
    /// Break-check: return a fixed-length body from `keepalive_pad_body` and
    /// this goes red.
    #[test]
    fn a_keepalive_does_not_have_one_size() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            seen.insert(build_keepalive_frame().len());
        }
        assert!(
            seen.len() > 8,
            "keepalive sizes collapsed to {} distinct value(s)",
            seen.len()
        );
    }

    /// The bytes must be random too: a constant filler would be as matchable
    /// as a constant length once a classifier looks past the size.
    #[test]
    fn the_padding_bytes_are_not_a_constant() {
        let a = keepalive_pad_body();
        let b = keepalive_pad_body();
        assert!(
            a != b || a.iter().collect::<std::collections::HashSet<_>>().len() > 1,
            "padding bodies look constant"
        );
    }

    /// Fresh probe is unarmed.  Sanity check for the constructor.
    #[test]
    fn fresh_probe_is_unarmed() {
        let probe = PendingKeepaliveProbe::new();
        assert!(!probe.is_armed());
        assert_eq!(probe.oldest(), None);
    }

    /// First `try_arm` returns `false` (was-not-armed) and records
    /// the timestamp.  Followup reads see the recorded timestamp.
    #[test]
    fn first_arm_records_timestamp_and_returns_was_not_set() {
        let mut probe = PendingKeepaliveProbe::new();
        let t0 = tokio::time::Instant::now();
        let was_already_armed = probe.try_arm(t0);
        assert!(!was_already_armed, "first arm: must report was_not_armed");
        assert!(probe.is_armed());
        assert_eq!(probe.oldest(), Some(t0));
    }

    /// **Oldest-preserved invariant** — a second `try_arm` after the
    /// first must NOT overwrite the recorded timestamp.  Returns
    /// `true` (was-already-armed).  Without this property the
    /// keepalive-probe timeout could not fire under steady keepalive
    /// load (see module doc).
    #[test]
    fn second_arm_preserves_oldest_timestamp_and_returns_was_set() {
        let mut probe = PendingKeepaliveProbe::new();
        let t0 = tokio::time::Instant::now();
        let t1 = t0 + std::time::Duration::from_secs(1);
        probe.try_arm(t0);
        let was_already_armed = probe.try_arm(t1);
        assert!(was_already_armed, "second arm: must report was_armed");
        assert_eq!(
            probe.oldest(),
            Some(t0),
            "oldest-preserved invariant: timestamp must stay at t0, not advance to t1",
        );
    }

    /// `clear` resets the ledger; subsequent `try_arm` behaves as
    /// if fresh.
    #[test]
    fn clear_resets_ledger() {
        let mut probe = PendingKeepaliveProbe::new();
        let t0 = tokio::time::Instant::now();
        probe.try_arm(t0);
        probe.clear();
        assert!(!probe.is_armed());
        assert_eq!(probe.oldest(), None);
        // A new arm starts from the new now, not the cleared t0.
        let t2 = t0 + std::time::Duration::from_secs(10);
        let was_armed = probe.try_arm(t2);
        assert!(!was_armed);
        assert_eq!(probe.oldest(), Some(t2));
    }
}
