//! Plaintext format of a sealed push envelope.
//!
//! The relay's X25519 secret unseals the envelope to recover these
//! bytes. The format is intentionally simple and provider-tagged so
//! a relay configured for FCM only does not accidentally fire an
//! APNs token (or vice-versa).
//!
//! ## Wire layout
//!
//! ```text
//! [0] provider u8 (0 = FCM, 1 = APNs)
//! [1..3] token_len u16 BE (≤ MAX_PROVIDER_TOKEN_LEN)
//! [3..3+token_len] token bytes
//! ```
//!
//! Total ≤ 1 + 2 + [`MAX_PROVIDER_TOKEN_LEN`] = 387 bytes, which
//! comfortably fits inside the 384-byte cap that
//! `veil-anonymity::push_envelope::MAX_PUSH_TOKEN_LEN` imposes
//! on the *plaintext* token (the AEAD overhead brings it under the
//! 512-byte envelope cap).

use crate::PushError;

/// Maximum length of the provider-specific token bytes.
///
/// FCM v1 registration tokens are typically 140-200 chars (base64-ish);
/// APNs device tokens are 32 bytes (raw) or 64 hex chars. 384 leaves
/// generous headroom for future provider quirks (UnifiedPush has
/// arbitrary-length endpoints).
pub const MAX_PROVIDER_TOKEN_LEN: usize = 384;

/// Push provider tag. Wire byte (0/1) — values are stable; new
/// providers append.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushProvider {
    /// Firebase Cloud Messaging (Google).
    Fcm = 0,
    /// Apple Push Notification service.
    Apns = 1,
}

impl PushProvider {
    /// Decode from a wire byte. Unknown values return
    /// [`PushError::InvalidToken`] so a misconfigured client cannot
    /// silently exploit a future-reserved tag.
    pub fn from_wire(b: u8) -> Result<Self, PushError> {
        match b {
            0 => Ok(Self::Fcm),
            1 => Ok(Self::Apns),
            other => Err(PushError::InvalidToken(format!(
                "unknown push provider byte: {other}",
            ))),
        }
    }
}

/// Decoded plaintext push token (the seal payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushToken {
    /// Which provider's API to call.
    pub provider: PushProvider,
    /// Provider-specific token bytes (FCM registration token, APNs
    /// device token, etc.).
    pub token: Vec<u8>,
}

impl PushToken {
    /// Encode to the wire-byte format documented at the module level.
    pub fn encode(&self) -> Vec<u8> {
        debug_assert!(self.token.len() <= MAX_PROVIDER_TOKEN_LEN);
        debug_assert!(self.token.len() <= u16::MAX as usize);
        let mut buf = Vec::with_capacity(3 + self.token.len());
        buf.push(self.provider as u8);
        buf.extend_from_slice(&(self.token.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.token);
        buf
    }

    /// Parse from wire bytes. Returns [`PushError::InvalidToken`] on
    /// any framing issue (unknown provider, bad length, truncated).
    pub fn decode(buf: &[u8]) -> Result<Self, PushError> {
        if buf.len() < 3 {
            return Err(PushError::InvalidToken(format!(
                "token plaintext too short: {} < 3",
                buf.len(),
            )));
        }
        let provider = PushProvider::from_wire(buf[0])?;
        let token_len = u16::from_be_bytes([buf[1], buf[2]]) as usize;
        if token_len > MAX_PROVIDER_TOKEN_LEN {
            return Err(PushError::InvalidToken(format!(
                "token_len {token_len} > {MAX_PROVIDER_TOKEN_LEN}",
            )));
        }
        if buf.len() < 3 + token_len {
            return Err(PushError::InvalidToken(format!(
                "token truncated: need {}, got {}",
                3 + token_len,
                buf.len(),
            )));
        }
        Ok(Self {
            provider,
            token: buf[3..3 + token_len].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t1_4_p3a_push_token_round_trip_fcm() {
        let t = PushToken {
            provider: PushProvider::Fcm,
            token: b"fake-fcm-registration-token-base64-ish".to_vec(),
        };
        let buf = t.encode();
        let d = PushToken::decode(&buf).unwrap();
        assert_eq!(d, t);
    }

    #[test]
    fn t1_4_p3a_push_token_round_trip_apns() {
        let t = PushToken {
            provider: PushProvider::Apns,
            token: vec![0xAB; 32],
        };
        let buf = t.encode();
        let d = PushToken::decode(&buf).unwrap();
        assert_eq!(d, t);
    }

    #[test]
    fn t1_4_p3a_push_token_max_size_round_trip() {
        let t = PushToken {
            provider: PushProvider::Fcm,
            token: vec![0xCD; MAX_PROVIDER_TOKEN_LEN],
        };
        let buf = t.encode();
        let d = PushToken::decode(&buf).unwrap();
        assert_eq!(d, t);
    }

    #[test]
    fn t1_4_p3a_push_token_unknown_provider_rejected() {
        let buf = [99u8, 0, 0];
        match PushToken::decode(&buf) {
            Err(PushError::InvalidToken(msg)) => {
                assert!(msg.contains("unknown push provider"));
            }
            other => panic!("expected InvalidToken, got {:?}", other),
        }
    }

    #[test]
    fn t1_4_p3a_push_token_too_short_rejected() {
        match PushToken::decode(&[0u8, 0]) {
            Err(PushError::InvalidToken(_)) => {}
            other => panic!("expected InvalidToken, got {:?}", other),
        }
    }

    #[test]
    fn t1_4_p3a_push_token_oversized_len_rejected() {
        let mut buf = vec![0u8]; // FCM
        let oversized = (MAX_PROVIDER_TOKEN_LEN + 1) as u16;
        buf.extend_from_slice(&oversized.to_be_bytes());
        match PushToken::decode(&buf) {
            Err(PushError::InvalidToken(msg)) => {
                assert!(msg.contains("token_len"));
            }
            other => panic!("expected InvalidToken, got {:?}", other),
        }
    }

    #[test]
    fn t1_4_p3a_push_token_truncated_body_rejected() {
        let mut buf = vec![0u8]; // FCM
        buf.extend_from_slice(&100u16.to_be_bytes());
        buf.extend_from_slice(&[0u8; 50]); // only 50 bytes
        match PushToken::decode(&buf) {
            Err(PushError::InvalidToken(msg)) => {
                assert!(msg.contains("truncated"));
            }
            other => panic!("expected InvalidToken, got {:?}", other),
        }
    }
}
