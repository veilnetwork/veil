//! Cross-crate test-fixture helpers (Phase 4/5 extraction left identical
//! copies в veil-cfg, veil-cli, veil-node-runtime, veilcore).
//! Each copy is referenced by ITS crate's own #[cfg(test)] code only;
//! dead_code suppressed crate-wide for the module because some fixtures
//! (`scratch_dir`, `fast_pow_params`, `identity_with_*_nonce`) ара used
//! только subsets of the four crates yet must stay identical для
//! handoff-readability.  Audit anchor: TASKS.md audit batch 2026-05-22.
#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use crate::cfg::{IdentityConfig, SignatureAlgorithm};
use crate::crypto;
use crate::identity_ops::IdentityPowParams;

/// Build a collision-free scratch directory under `std::env::temp_dir` and
/// ensure it exists. 128 bits of `OsRng` entropy + `process::id` guarantee
/// uniqueness across parallel tests, across cargo-test processes (nextest)
/// and across re-runs (stale leftovers from a crashed run can't be reused).
///
/// On WSL2 ext4, `/tmp` suffers transient `EACCES` under heavy concurrent
/// `openat`/`mkdirat` load (kernel-level race during directory-entry cache
/// rebuild). The caller's first `mkdirat` is retried up to 3× with 25/50ms
/// backoff to paper over these transients — real permission failures still
/// propagate as a panic after the retries.
pub(crate) fn scratch_dir(prefix: &str) -> PathBuf {
    use rand_core::{OsRng, RngCore};
    let nonce: u128 = ((OsRng.next_u64() as u128) << 64) | OsRng.next_u64() as u128;
    let dir = std::env::temp_dir().join(format!("{prefix}-{}-{:032x}", std::process::id(), nonce,));
    for attempt in 0..3 {
        match std::fs::create_dir_all(&dir) {
            Ok(()) => return dir,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied && attempt < 2 => {
                std::thread::sleep(Duration::from_millis(25 * (attempt as u64 + 1)));
            }
            Err(e) => panic!("test_support::scratch_dir({prefix}) failed: {e}"),
        }
    }
    unreachable!()
}

pub(crate) fn ed25519_keypair() -> crypto::GeneratedKeyPair {
    crypto::generate_keypair(SignatureAlgorithm::Ed25519)
}

pub(crate) fn fast_pow_params() -> IdentityPowParams {
    IdentityPowParams {
        difficulty: 1,
        timeout: Duration::from_secs(2),
        threads: 1,
    }
}

pub(crate) fn valid_identity() -> IdentityConfig {
    static VALID_IDENTITY: OnceLock<IdentityConfig> = OnceLock::new();

    VALID_IDENTITY
        .get_or_init(|| {
            let keypair = ed25519_keypair();
            let result = crypto::search_nonce(crypto::PowParams {
                algo: SignatureAlgorithm::Ed25519,
                public_key: crypto::Base64PublicKey::new(
                    SignatureAlgorithm::Ed25519,
                    keypair.public_key.clone(),
                )
                .expect("valid public key"),
                private_key: crypto::Base64PrivateKey::new(
                    SignatureAlgorithm::Ed25519,
                    keypair.private_key.clone(),
                )
                .expect("valid private key"),
                target_zero_bits: crypto::DEFAULT_POW_DIFFICULTY,
                // Bumped from 30s — slow CI runners (shared GitHub Actions
                // containers) occasionally fail to hit the target inside 30s
                // which used to return a best-effort nonce that failed later
                // config validation with a confusing "must produce at least N
                // leading zero bits" error.
                timeout: Duration::from_secs(300),
                start_from: crypto::Base64Nonce::zero(),
                threads: crypto::available_thread_count(),
                progress: None,
            })
            .expect("pow result");

            // Fail loudly if the search timed out rather than returning a
            // best-effort nonce whose score is below `target_zero_bits`.
            // Without this, downstream config validation trips with a
            // misleading error far from the root cause.
            assert_eq!(
                result.stop_reason,
                crypto::PowStopReason::Found,
                "test_support::valid_identity: PoW search did not reach target {} bits \
                 within timeout (best={} bits, reason={:?}) — CI runner too slow or \
                 difficulty misconfigured",
                crypto::DEFAULT_POW_DIFFICULTY,
                result.best_zero_bits,
                result.stop_reason,
            );

            IdentityConfig {
                algo: SignatureAlgorithm::Ed25519,
                role: Default::default(),
                public_key: keypair.public_key,
                private_key: keypair.private_key,
                nonce: result.best_nonce.into_inner(),
                node_id: None,
                key_passphrase: None,
                key_passphrase_file: None,
                key_passphrase_prompt: false,
                lazy_mining: true,
                max_lazy_difficulty: 64,
            }
        })
        .clone()
}

pub(crate) fn identity_with_invalid_nonce() -> IdentityConfig {
    let valid = valid_identity();

    IdentityConfig {
        nonce: crypto::Base64Nonce::zero().into_inner(),
        ..valid
    }
}

pub(crate) fn identity_with_nonce_below(difficulty: u32) -> IdentityConfig {
    loop {
        let keypair = ed25519_keypair();
        let public_key =
            crypto::Base64PublicKey::new(SignatureAlgorithm::Ed25519, keypair.public_key.clone())
                .expect("valid public key");
        let private_key =
            crypto::Base64PrivateKey::new(SignatureAlgorithm::Ed25519, keypair.private_key.clone())
                .expect("valid private key");
        let nonce = crypto::Base64Nonce::zero();
        let score = crypto::pow_score(
            SignatureAlgorithm::Ed25519,
            &public_key,
            &private_key,
            &nonce,
        )
        .expect("pow score");

        if score.zero_bits < difficulty {
            return IdentityConfig {
                algo: SignatureAlgorithm::Ed25519,
                role: Default::default(),
                public_key: keypair.public_key,
                private_key: keypair.private_key,
                nonce: nonce.into_inner(),
                node_id: None,
                key_passphrase: None,
                key_passphrase_file: None,
                key_passphrase_prompt: false,
                lazy_mining: true,
                max_lazy_difficulty: 64,
            };
        }
    }
}
