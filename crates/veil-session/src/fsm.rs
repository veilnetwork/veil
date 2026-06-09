//! Session state machine for the OVL1 session handshake.
//!
//! A session progresses through the following states (initiator view):
//!
//! ```text
//! Init
//! └─(send HELLO)──► HelloSent
//! └─(recv HELLO)──► IdentitySent
//! └─(recv IDENTITY)──► CapabilitiesSent
//! └─(recv CAPABILITIES)──► KeyAgreementSent
//! └─(recv KEY_AGREEMENT)──► ConfirmSent
//! └─(recv SESSION_CONFIRM)──► AttachSent
//! └─(recv ATTACH)──► Attached
//! ```
//!
//! The responder mirrors the same transitions. Both sides track which
//! messages they have *sent* and *received*; the `advance` method is called
//! after each successful decode to enforce the strict ordering.

use veil_proto::session::{
    AttachPayload, CapabilitiesPayload, HelloPayload, IdentityPayload, KeyAgreementPayload,
    SessionConfirmPayload, SessionTicket,
};

/// All states the session FSM can be in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionPhase {
    /// No messages exchanged yet.
    Init,
    /// HELLO has been sent; waiting for remote HELLO.
    HelloSent,
    /// Both HELLOs exchanged; IDENTITY has been sent.
    IdentitySent,
    /// Both IDENTITYs exchanged; CAPABILITIES has been sent.
    CapabilitiesSent,
    /// Both CAPABILITIES exchanged; KEY_AGREEMENT has been sent.
    KeyAgreementSent,
    /// Both KEY_AGREEMENTs exchanged; SESSION_CONFIRM has been sent.
    ConfirmSent,
    /// Both SESSION_CONFIRMs exchanged; ATTACH has been sent.
    AttachSent,
    /// Full handshake complete — session is live.
    Attached,
    /// Resumption path: HELLO with ticket sent, awaiting server's RESUME_ACK.
    ResumptionSent,
    /// Resumption path: server accepted ticket, fast-path complete — session is live.
    ResumptionAccepted,
    /// Terminal error state — session must be torn down.
    Failed(String),
}

impl SessionPhase {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            SessionPhase::Attached | SessionPhase::ResumptionAccepted | SessionPhase::Failed(_)
        )
    }

    /// Return the failure reason if in `Failed` state, or `None` otherwise.
    pub fn failed_reason(&self) -> Option<&str> {
        if let SessionPhase::Failed(reason) = self {
            Some(reason)
        } else {
            None
        }
    }
}

/// Accumulated data learned during the handshake.
#[derive(Debug, Clone, Default)]
pub struct SessionHandshakeData {
    pub remote_hello: Option<HelloPayload>,
    pub remote_identity: Option<IdentityPayload>,
    pub remote_capabilities: Option<CapabilitiesPayload>,
    pub remote_key_agreement: Option<KeyAgreementPayload>,
    pub remote_confirm: Option<SessionConfirmPayload>,
    pub remote_attach: Option<AttachPayload>,
    /// Plaintext ticket recovered by the server during a resumption fast-path.
    pub resumed_ticket: Option<SessionTicket>,
}

/// Session finite state machine.
#[derive(Debug)]
pub struct SessionFsm {
    pub phase: SessionPhase,
    pub data: SessionHandshakeData,
}

impl SessionFsm {
    pub fn new() -> Self {
        Self {
            phase: SessionPhase::Init,
            data: SessionHandshakeData::default(),
        }
    }

    // ── outbound events (local side sends a message) ──────────────────────

    /// Record that we have sent a HELLO frame.
    pub fn on_hello_sent(&mut self) {
        if self.require_phase(SessionPhase::Init, "HELLO") {
            self.phase = SessionPhase::HelloSent;
        }
    }

    /// Record that we have sent an IDENTITY frame.
    pub fn on_identity_sent(&mut self) {
        if self.require_phase(SessionPhase::HelloSent, "IDENTITY") {
            self.phase = SessionPhase::IdentitySent;
        }
    }

    /// Record that we have sent a CAPABILITIES frame.
    pub fn on_capabilities_sent(&mut self) {
        if self.require_phase(SessionPhase::IdentitySent, "CAPABILITIES") {
            self.phase = SessionPhase::CapabilitiesSent;
        }
    }

    /// Record that we have sent a KEY_AGREEMENT frame.
    pub fn on_key_agreement_sent(&mut self) {
        if self.require_phase(SessionPhase::CapabilitiesSent, "KEY_AGREEMENT") {
            self.phase = SessionPhase::KeyAgreementSent;
        }
    }

    /// Record that we have sent a SESSION_CONFIRM frame.
    pub fn on_confirm_sent(&mut self) {
        if self.require_phase(SessionPhase::KeyAgreementSent, "SESSION_CONFIRM") {
            self.phase = SessionPhase::ConfirmSent;
        }
    }

    /// Record that we have sent an ATTACH frame.
    pub fn on_attach_sent(&mut self) {
        if self.require_phase(SessionPhase::ConfirmSent, "ATTACH") {
            self.phase = SessionPhase::AttachSent;
        }
    }

    // ── inbound events (remote sends a message) ───────────────────────────

    /// Process a received HELLO payload.
    pub fn on_hello_received(&mut self, payload: HelloPayload) {
        if !matches!(self.phase, SessionPhase::HelloSent) {
            self.fail(format!("unexpected HELLO in phase {:?}", self.phase));
            return;
        }
        self.data.remote_hello = Some(payload);
    }

    /// Process a received IDENTITY payload.
    pub fn on_identity_received(&mut self, payload: IdentityPayload) {
        if !matches!(self.phase, SessionPhase::IdentitySent) {
            self.fail(format!("unexpected IDENTITY in phase {:?}", self.phase));
            return;
        }
        self.data.remote_identity = Some(payload);
    }

    /// Process a received CAPABILITIES payload.
    pub fn on_capabilities_received(&mut self, payload: CapabilitiesPayload) {
        if !matches!(self.phase, SessionPhase::CapabilitiesSent) {
            self.fail(format!("unexpected CAPABILITIES in phase {:?}", self.phase));
            return;
        }
        self.data.remote_capabilities = Some(payload);
    }

    /// Process a received KEY_AGREEMENT payload.
    pub fn on_key_agreement_received(&mut self, payload: KeyAgreementPayload) {
        if !matches!(self.phase, SessionPhase::KeyAgreementSent) {
            self.fail(format!(
                "unexpected KEY_AGREEMENT in phase {:?}",
                self.phase
            ));
            return;
        }
        self.data.remote_key_agreement = Some(payload);
    }

    /// Process a received SESSION_CONFIRM payload.
    pub fn on_confirm_received(&mut self, payload: SessionConfirmPayload) {
        if !matches!(self.phase, SessionPhase::ConfirmSent) {
            self.fail(format!(
                "unexpected SESSION_CONFIRM in phase {:?}",
                self.phase
            ));
            return;
        }
        self.data.remote_confirm = Some(payload);
    }

    /// Process a received ATTACH payload — transitions to `Attached`.
    pub fn on_attach_received(&mut self, payload: AttachPayload) {
        if !matches!(self.phase, SessionPhase::AttachSent) {
            self.fail(format!("unexpected ATTACH in phase {:?}", self.phase));
            return;
        }
        self.data.remote_attach = Some(payload);
        self.phase = SessionPhase::Attached;
    }

    // ── resumption-path transitions ────────────────────────────

    /// Record that we sent a HELLO that includes a resume_ticket.
    ///
    /// Transitions `Init → ResumptionSent`; the peer will either send a fast-path
    /// ATTACH (accept) or fall back to the standard HELLO response (reject).
    pub fn on_resumption_hello_sent(&mut self) {
        if self.require_phase(SessionPhase::Init, "RESUMPTION-HELLO") {
            self.phase = SessionPhase::ResumptionSent;
        }
    }

    /// Record that the server accepted the resume ticket and sent a fast-path ATTACH.
    ///
    /// Stores the decoded `ticket` so that the caller can restore session keys from
    /// the `tx_key` / `rx_key` fields. Transitions `ResumptionSent → ResumptionAccepted`.
    pub fn on_resumption_accepted(&mut self, ticket: SessionTicket) {
        if !matches!(self.phase, SessionPhase::ResumptionSent) {
            self.fail(format!("unexpected RESUME_ACK in phase {:?}", self.phase));
            return;
        }
        self.data.resumed_ticket = Some(ticket);
        self.phase = SessionPhase::ResumptionAccepted;
    }

    // ── internal helpers ──────────────────────────────────────────────────

    /// Returns `true` if the phase matches `expected`; sets `Failed` and returns `false` otherwise.
    fn require_phase(&mut self, expected: SessionPhase, msg_name: &str) -> bool {
        if self.phase != expected {
            self.fail(format!(
                "tried to send {msg_name} in phase {:?}",
                self.phase
            ));
            false
        } else {
            true
        }
    }

    fn fail(&mut self, reason: String) {
        self.phase = SessionPhase::Failed(reason);
    }
}

impl Default for SessionFsm {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_proto::session::{cap_flags, role_bits};

    fn make_hello() -> HelloPayload {
        HelloPayload {
            ovl1_major: 1,
            node_id: [0xAA; 32],
            resume_ticket: None,
            membership_cert_blob: None,
            resume_nonce: None,
        }
    }

    fn make_identity() -> IdentityPayload {
        IdentityPayload {
            algo: 1,
            public_key: vec![0x11; 32],
            nonce: b"nonce".to_vec(),
            node_id: [0xBB; 32],
            mlkem_pubkey: None,
        }
    }

    fn make_capabilities() -> CapabilitiesPayload {
        CapabilitiesPayload {
            roles_supported: role_bits::LEAF,
            flags: cap_flags::CAN_RELAY,
            discovery_mode: 0,
        }
    }

    fn make_key_agreement() -> KeyAgreementPayload {
        KeyAgreementPayload {
            algo: 1,
            ephemeral_pubkey: vec![0x22; 32],
            ephemeral_sig: vec![],
        }
    }

    fn make_confirm() -> SessionConfirmPayload {
        SessionConfirmPayload {
            session_id: [0xCC; 32],
            mac: [0xDD; 32],
        }
    }

    fn make_attach() -> AttachPayload {
        AttachPayload {
            role: 0,
            realm_id: 1,
            attach_epoch: 0,
            mailbox_preference_count: 0,
            gateway_preference_count: 0,
            flags: 0,
        }
    }

    #[test]
    fn full_handshake_happy_path() {
        let mut fsm = SessionFsm::new();
        assert_eq!(fsm.phase, SessionPhase::Init);

        fsm.on_hello_sent();
        assert_eq!(fsm.phase, SessionPhase::HelloSent);

        fsm.on_hello_received(make_hello());
        assert_eq!(fsm.phase, SessionPhase::HelloSent); // phase unchanged until we send next

        fsm.on_identity_sent();
        assert_eq!(fsm.phase, SessionPhase::IdentitySent);

        fsm.on_identity_received(make_identity());
        fsm.on_capabilities_sent();
        assert_eq!(fsm.phase, SessionPhase::CapabilitiesSent);

        fsm.on_capabilities_received(make_capabilities());
        fsm.on_key_agreement_sent();
        assert_eq!(fsm.phase, SessionPhase::KeyAgreementSent);

        fsm.on_key_agreement_received(make_key_agreement());
        fsm.on_confirm_sent();
        assert_eq!(fsm.phase, SessionPhase::ConfirmSent);

        fsm.on_confirm_received(make_confirm());
        fsm.on_attach_sent();
        assert_eq!(fsm.phase, SessionPhase::AttachSent);

        fsm.on_attach_received(make_attach());
        assert_eq!(fsm.phase, SessionPhase::Attached);
        assert!(fsm.phase.is_terminal());
    }

    #[test]
    fn out_of_order_message_fails() {
        let mut fsm = SessionFsm::new();
        // Send IDENTITY before HELLO — should fail
        fsm.on_identity_sent();
        assert!(matches!(fsm.phase, SessionPhase::Failed(_)));
        assert!(fsm.phase.is_terminal());
    }

    #[test]
    fn unexpected_inbound_fails() {
        let mut fsm = SessionFsm::new();
        fsm.on_hello_sent();
        // Receive IDENTITY while expecting HELLO — should fail
        fsm.on_identity_received(make_identity());
        assert!(matches!(fsm.phase, SessionPhase::Failed(_)));
    }
}
