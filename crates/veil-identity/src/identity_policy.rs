use std::time::Duration;

use veil_types::SignatureAlgorithm;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PowPolicy {
    pub difficulty: u32,
    pub timeout: Duration,
    pub threads: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityPolicy {
    pub algo: SignatureAlgorithm,
    pub pow: PowPolicy,
}

impl IdentityPolicy {
    pub const DEFAULT_ALGO: SignatureAlgorithm = SignatureAlgorithm::Ed25519;
    // c: POW defaults moved to `crypto::pow::score` so crypto/ no
    // longer reverse-imports identity_policy. Re-exported here to keep
    // existing call sites (`IdentityPolicy::DEFAULT_POW_*`) working.
    pub const DEFAULT_POW_DIFFICULTY: u32 = veil_crypto::DEFAULT_POW_DIFFICULTY;
    pub const DEFAULT_POW_TIMEOUT_SECS: u64 = veil_crypto::DEFAULT_POW_TIMEOUT_SECS;
    /// The canonical identity policy: the default signature algorithm paired
    /// with the canonical [`PowPolicy`].
    pub fn canonical() -> Self {
        Self {
            algo: Self::DEFAULT_ALGO,
            pow: PowPolicy::canonical(),
        }
    }
}

impl Default for IdentityPolicy {
    fn default() -> Self {
        Self::canonical()
    }
}

impl PowPolicy {
    pub fn canonical() -> Self {
        Self {
            difficulty: IdentityPolicy::DEFAULT_POW_DIFFICULTY,
            timeout: Duration::from_secs(IdentityPolicy::DEFAULT_POW_TIMEOUT_SECS),
            threads: veil_crypto::available_thread_count(),
        }
    }
}

impl Default for PowPolicy {
    fn default() -> Self {
        Self::canonical()
    }
}

#[cfg(test)]
mod tests {
    use super::{IdentityPolicy, PowPolicy};

    #[test]
    fn canonical_policy_matches_expected_defaults() {
        let identity = IdentityPolicy::canonical();
        let pow = PowPolicy::canonical();

        assert_eq!(identity.algo.to_string(), "ed25519");
        assert_eq!(
            identity.pow.difficulty,
            IdentityPolicy::DEFAULT_POW_DIFFICULTY
        );
        assert_eq!(
            identity.pow.timeout.as_secs(),
            IdentityPolicy::DEFAULT_POW_TIMEOUT_SECS
        );
        assert_eq!(identity.pow, pow);
        assert!(identity.pow.threads >= 1);
    }
}
