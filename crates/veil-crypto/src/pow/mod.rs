mod interrupt;
pub mod score;
mod search;
mod state;

pub use interrupt::reset_interrupt_flag;
pub use score::{
    DEFAULT_POW_DIFFICULTY, DEFAULT_POW_TIMEOUT_SECS, PowScore, available_thread_count,
    default_nonce_base64, pow_score,
};
pub use search::{PowParams, PowProgress, PowResult, PowStopReason, search_nonce};

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::{Base64Nonce, Base64PrivateKey, Base64PublicKey, generate_keypair};
    use veil_types::SignatureAlgorithm;

    fn ed25519_keypair() -> crate::GeneratedKeyPair {
        generate_keypair(SignatureAlgorithm::Ed25519)
    }

    mod unit {
        use super::*;

        #[test]
        fn calculates_pow_score() {
            let keypair = ed25519_keypair();
            let score = pow_score(
                SignatureAlgorithm::Ed25519,
                &Base64PublicKey::new(SignatureAlgorithm::Ed25519, keypair.public_key).unwrap(),
                &Base64PrivateKey::new(SignatureAlgorithm::Ed25519, keypair.private_key).unwrap(),
                &Base64Nonce::zero(),
            )
            .unwrap();
            assert!(score.zero_bits <= 256);
        }
    }

    mod integration_pow {
        use super::*;

        #[test]
        fn timeout_returns_stopped_position() {
            let keypair = ed25519_keypair();
            let result = search_nonce(PowParams {
                algo: SignatureAlgorithm::Ed25519,
                public_key: Base64PublicKey::new(SignatureAlgorithm::Ed25519, keypair.public_key)
                    .unwrap(),
                private_key: Base64PrivateKey::new(
                    SignatureAlgorithm::Ed25519,
                    keypair.private_key,
                )
                .unwrap(),
                target_zero_bits: 256,
                timeout: Duration::from_millis(1),
                start_from: Base64Nonce::zero(),
                threads: 1,
                progress: None,
            })
            .unwrap();

            assert_eq!(result.stop_reason, PowStopReason::Timeout);
            assert!(!result.stopped_at.as_str().is_empty());
        }
    }
}
