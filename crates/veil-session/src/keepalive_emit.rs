//! SessionRunner decomposition slice 24: keepalive emission + probe-ack
//! ledger.
//!
//! Bundles two related pieces:
//!
//! 1. [`build_keepalive_frame`] — pure-function frame builder
//!    (`Control / Keepalive` with zero-byte body).  Used inline on the
//!    keepalive-due tick.
//! 2. [`PendingKeepaliveProbe`] — Option<Instant> wrapper с
//!    **oldest-preserved** try_arm semantics: when а keepalive is
//!    emitted while а previous probe is still unacked, the existing
//!    timestamp is preserved so the probe-timeout measures the
//!    longest unacked window rather than the most recent.  Tied к
//!    Epic 459 stage (c.2.2) hot-standby TX-health detection.
//!
//! # Why extracted
//!
//! Pre-slice the keepalive emission lived inline в SessionRunner::run()
//! as 33 LoC of header construction + pq.push + side-effect log +
//! manual `Option::is_none` armé.  Awkward к unit-test (would require
//! spinning up а full session) и repeated `is_some()` / `is_none()`
//! checks across run() и compute_sleep_deadline().
//!
//! After: emission is а 3-line push, и `PendingKeepaliveProbe` provides
//! semantically-named methods (`try_arm` / `oldest` / `clear` /
//! `is_armed`) с 5 unit tests pinning the oldest-preserved invariant.

use veil_proto::{ControlMsg, codec::encode_header, family::FrameFamily, header::FrameHeader};

/// Build а `Control / Keepalive` frame ready к push to the priority
/// queue.  Zero-byte body — keepalive is а pure liveness ping; no
/// payload semantics.  Cheap (one header encode); idempotent —
/// returns а fresh `Vec<u8>` on every call.
pub fn build_keepalive_frame() -> Vec<u8> {
    let mut hdr = FrameHeader::new(FrameFamily::Control as u8, ControlMsg::Keepalive as u16);
    hdr.body_len = 0;
    encode_header(&hdr).to_vec()
}

/// Ledger of an in-flight keepalive-ack expectation, tied to Epic 459
/// stage (c.2.2) hot-standby TX-health detection.
///
/// # Why oldest-preserved
///
/// The probe-timeout measures *how long we've been waiting for any
/// ack* — not "how long since the most recent keepalive."  Consider:
/// keepalive_interval = 1 s, keepalive_probe_timeout = 5 s.  Peer dies
/// silently at t=0.  Без the oldest-preserved invariant, at t=0 we
/// arm с probe_since=0, at t=1 а new keepalive overwrites
/// probe_since=1, etc.  At t=5 probe_since=5, `now - probe_since = 0`,
/// timeout never fires.  The TX-health trigger silently stays off
/// forever и the session sits dead.
///
/// С oldest-preserved: t=0 arms probe_since=0, t=1's keepalive sees
/// the existing probe_since и leaves it alone.  At t=5 the timeout
/// fires correctly.
#[derive(Debug, Default, Clone, Copy)]
pub struct PendingKeepaliveProbe {
    /// Timestamp of the OLDEST unacked keepalive.  `None` когда no probe
    /// is outstanding (after а KeepaliveAck arrives).
    armed_at: Option<tokio::time::Instant>,
}

impl PendingKeepaliveProbe {
    /// Construct а new ledger в the "no pending probe" state.
    pub fn new() -> Self {
        Self { armed_at: None }
    }

    /// Arm the probe if no prior probe is already armed.  Returns
    /// **`true`** когда the probe was already armed (the caller's
    /// keepalive frame piggybacks on an existing probe-timeout
    /// window); **`false`** когда this is а fresh arm.  Surface
    /// matches the inline-code intent: `let was_pending_set =
    /// probe.try_arm(now);`.
    pub fn try_arm(&mut self, now: tokio::time::Instant) -> bool {
        let was_armed = self.armed_at.is_some();
        if !was_armed {
            self.armed_at = Some(now);
        }
        was_armed
    }

    /// Whether а probe is currently armed.  Cheap accessor — used by
    /// the debug-log "was_set" field and by [`Self::oldest`]'s caller
    /// when an `Option<Instant>` is а cleaner shape than а bool +
    /// follow-up read.
    pub fn is_armed(&self) -> bool {
        self.armed_at.is_some()
    }

    /// Timestamp of the oldest unacked keepalive, OR `None` если none
    /// is pending.  Used by:
    /// * `compute_sleep_deadline` к set the probe-timeout wake-up.
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

    /// `build_keepalive_frame` must encode а valid Control/Keepalive
    /// frame с zero-byte body.  Wire shape is checked by decoding
    /// the result back through the same codec.
    #[test]
    fn build_frame_decodes_as_control_keepalive_zero_body() {
        let frame = build_keepalive_frame();
        let hdr = decode_header(&frame).expect("decodes");
        assert_eq!(hdr.family, FrameFamily::Control as u8);
        assert_eq!(hdr.msg_type, ControlMsg::Keepalive as u16);
        assert_eq!(hdr.body_len, 0);
        assert_eq!(
            frame.len(),
            veil_proto::header::HEADER_SIZE,
            "zero-body keepalive must be exactly HEADER_SIZE bytes"
        );
    }

    /// Fresh probe is unarmed.  Sanity check для the constructor.
    #[test]
    fn fresh_probe_is_unarmed() {
        let probe = PendingKeepaliveProbe::new();
        assert!(!probe.is_armed());
        assert_eq!(probe.oldest(), None);
    }

    /// First `try_arm` returns `false` (was-not-armed) и records
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

    /// **Oldest-preserved invariant** — а second `try_arm` after the
    /// first must NOT overwrite the recorded timestamp.  Returns
    /// `true` (was-already-armed).  Without this property the
    /// keepalive-probe timeout could не fire under steady keepalive
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
            "oldest-preserved invariant: timestamp must stay at t0, not advance к t1",
        );
    }

    /// `clear` resets the ledger; subsequent `try_arm` behaves as
    /// если fresh.
    #[test]
    fn clear_resets_ledger() {
        let mut probe = PendingKeepaliveProbe::new();
        let t0 = tokio::time::Instant::now();
        probe.try_arm(t0);
        probe.clear();
        assert!(!probe.is_armed());
        assert_eq!(probe.oldest(), None);
        // А new arm starts from the new now, not the cleared t0.
        let t2 = t0 + std::time::Duration::from_secs(10);
        let was_armed = probe.try_arm(t2);
        assert!(!was_armed);
        assert_eq!(probe.oldest(), Some(t2));
    }
}
