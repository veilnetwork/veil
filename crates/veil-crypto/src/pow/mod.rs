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

        #[test]
        fn pow_score_matches_worker_path_for_hybrid() {
            // audit cycle-8 H13 — pow_score (initial-score seed + verification)
            // must agree byte-for-byte with the search-loop scorer
            // (pow_score_raw via CachedSigningKey) for a hybrid algo, which signs
            // Ed25519-ONLY. Before the fix pow_score signed the full
            // [ed_sig][falcon_sig] and produced a different zero_bits, so a nonce
            // the workers found was not verifiable via pow_score.
            use crate::pow::score;
            let algo = SignatureAlgorithm::Ed25519Falcon512Hybrid;
            let kp = generate_keypair(algo);
            let pk = Base64PublicKey::new(algo, kp.public_key.clone()).unwrap();
            let sk = Base64PrivateKey::new(algo, kp.private_key.clone()).unwrap();
            let nonce = Base64Nonce::zero();

            let via_pow_score = pow_score(algo, &pk, &sk, &nonce).unwrap();

            let pk_bytes = score::decode_pk_bytes(algo, &pk).unwrap();
            let sk_bytes = score::decode_sk_bytes(algo, &sk).unwrap();
            let signing_key = score::CachedSigningKey::from_private_key(algo, &sk_bytes).unwrap();
            let nonce_bytes = score::decode_nonce(nonce.as_str()).unwrap();
            let via_worker = score::pow_score_raw(&pk_bytes, &signing_key, &nonce_bytes).unwrap();

            assert_eq!(
                via_pow_score.zero_bits, via_worker.zero_bits,
                "pow_score must equal the worker scorer for hybrid (H13)"
            );
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
