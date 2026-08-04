//! The post-quantum leg: one ML-KEM-768 epoch of the ratchet.
//!
//! ML-KEM is a one-shot KEM, not a Diffie-Hellman. There is no operation that
//! both parties can compute independently from public values, so it cannot be
//! dropped into the asymmetric ratchet the way X25519 is — a naive
//! substitution breaks out-of-order delivery, because every message would need
//! its own round trip.
//!
//! The fix, which is what Signal's post-quantum ratchet also does at heart, is
//! to bind the KEM round trip to the **epoch** rather than to the message:
//!
//! * Every outgoing header announces our current encapsulation key.
//! * When the peer takes an asymmetric step, they encapsulate to the key we
//!   announced and carry the ciphertext in their headers until their next
//!   step.
//! * Both operations happen inside one asymmetric step, so the resulting
//!   shared secret belongs to exactly one epoch. Every message inside an epoch
//!   rides the same chain key, so reordering and loss are handled by the
//!   symmetric ratchet exactly as they were before.
//!
//! The cost is size: 1184 bytes of encapsulation key and 1088 bytes of
//! ciphertext ride along until the epoch turns. That is deliberate — carrying
//! them on every message is what lets a lost message not strand the epoch.

use ml_kem::array::Array;
use ml_kem::kem::DecapsulationKey;
use ml_kem::ml_kem_768::EncapsulationKey as Ek768;
use ml_kem::{B32, Ciphertext, Decapsulate, Key, KeyExport, MlKem768, Seed};
use zeroize::Zeroizing;

use crate::{KEY_LEN, RatchetError, RatchetRng, random_array};

type Dk768 = DecapsulationKey<MlKem768>;

/// Byte length of an ML-KEM-768 encapsulation key.
pub const ML_KEM_768_EK_LEN: usize = 1184;
/// Byte length of an ML-KEM-768 ciphertext.
pub const ML_KEM_768_CT_LEN: usize = 1088;
/// Byte length of an ML-KEM-768 decapsulation seed.
///
/// The seed, not the expanded 2400-byte private key, is what gets persisted:
/// it regenerates the keypair exactly and is 37× smaller.
pub const ML_KEM_768_SEED_LEN: usize = 64;

/// Our ML-KEM-768 state for the current epoch.
#[derive(Clone)]
pub(crate) struct PqEpoch {
    /// Seed for our decapsulation key. Held rather than the expanded key so
    /// that exporting the session is cheap and the expanded key never has to
    /// leave the process in serialized form.
    seed: Zeroizing<[u8; ML_KEM_768_SEED_LEN]>,
    /// Our encapsulation key, pre-serialized for insertion into headers.
    ek: [u8; ML_KEM_768_EK_LEN],
    /// Our answer to the encapsulation key the peer most recently announced.
    /// Rides in every outgoing header until our next asymmetric step replaces
    /// it, so losing the message that first carried it is survivable.
    pending_ct: Option<[u8; ML_KEM_768_CT_LEN]>,
}

impl core::fmt::Debug for PqEpoch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PqEpoch")
            .field("has_pending_ct", &self.pending_ct.is_some())
            .finish_non_exhaustive()
    }
}

impl PqEpoch {
    /// Start a fresh epoch with a new keypair and no answer outstanding.
    pub(crate) fn new(rng: &mut impl RatchetRng) -> Self {
        let seed = random_array::<ML_KEM_768_SEED_LEN>(rng);
        Self::from_seed(seed, None)
    }

    fn from_seed(
        seed: Zeroizing<[u8; ML_KEM_768_SEED_LEN]>,
        pending_ct: Option<[u8; ML_KEM_768_CT_LEN]>,
    ) -> Self {
        let arr: Seed = Array(*seed);
        let dk = Dk768::from_seed(arr);
        let ek_bytes = dk.encapsulation_key().to_bytes();
        let mut ek = [0u8; ML_KEM_768_EK_LEN];
        ek.copy_from_slice(ek_bytes.as_slice());
        Self {
            seed,
            ek,
            pending_ct,
        }
    }

    /// Rebuild an epoch from persisted parts.
    pub(crate) fn restore(
        seed: &[u8; ML_KEM_768_SEED_LEN],
        pending_ct: Option<[u8; ML_KEM_768_CT_LEN]>,
    ) -> Self {
        Self::from_seed(Zeroizing::new(*seed), pending_ct)
    }

    /// Our encapsulation key, for the outgoing header.
    pub(crate) fn ek(&self) -> &[u8; ML_KEM_768_EK_LEN] {
        &self.ek
    }

    /// The seed, for persistence.
    pub(crate) fn seed(&self) -> &[u8; ML_KEM_768_SEED_LEN] {
        &self.seed
    }

    /// The outstanding answer, for the outgoing header and for persistence.
    pub(crate) fn pending_ct(&self) -> Option<&[u8; ML_KEM_768_CT_LEN]> {
        self.pending_ct.as_ref()
    }

    pub(crate) fn set_pending_ct(&mut self, ct: [u8; ML_KEM_768_CT_LEN]) {
        self.pending_ct = Some(ct);
    }

    /// Decapsulate the peer's answer to the key we announced.
    ///
    /// ML-KEM decapsulation does not fail on a wrong ciphertext — FIPS 203
    /// specifies implicit rejection, so a forged ciphertext yields a
    /// pseudo-random secret instead of an error. That is exactly why the
    /// session commits nothing until the AEAD tag verifies: a forgery derives
    /// the wrong chain key, the tag fails, and the whole step is rolled back.
    pub(crate) fn decapsulate(&self, ct: &[u8; ML_KEM_768_CT_LEN]) -> [u8; KEY_LEN] {
        let arr: Ciphertext<MlKem768> =
            Array::try_from(ct.as_slice()).expect("ML_KEM_768_CT_LEN is the ciphertext size");
        let dk = Dk768::from_seed(Array(*self.seed));
        let ss = dk.decapsulate(&arr);
        let mut out = [0u8; KEY_LEN];
        out.copy_from_slice(ss.as_slice());
        out
    }
}

/// Encapsulate to a peer's announced encapsulation key.
///
/// Rejects a structurally invalid key rather than deriving from garbage: an
/// invalid key on the wire is a forgery attempt, not a peer with a
/// disagreement about encoding.
pub(crate) fn encapsulate_to(
    peer_ek: &[u8; ML_KEM_768_EK_LEN],
    rng: &mut impl RatchetRng,
) -> Result<([u8; KEY_LEN], [u8; ML_KEM_768_CT_LEN]), RatchetError> {
    let key_arr: Key<Ek768> = Array::try_from(peer_ek.as_slice())
        .expect("ML_KEM_768_EK_LEN is the encapsulation-key size");
    let ek = Ek768::new(&key_arr).map_err(|_| RatchetError::InvalidPqKey)?;

    // `encapsulate_deterministic` is FIPS 203's `ML-KEM.Encaps_internal`: it
    // takes the 32 bytes of randomness explicitly instead of reaching for a
    // system RNG. Using it keeps this crate on one randomness source and lets
    // the tests pin end-to-end vectors.
    let m = random_array::<32>(rng);
    let m: B32 = Array(*m);
    let (ct, ss) = ek.encapsulate_deterministic(&m);

    let mut ct_bytes = [0u8; ML_KEM_768_CT_LEN];
    ct_bytes.copy_from_slice(ct.as_slice());
    let mut ss_bytes = [0u8; KEY_LEN];
    ss_bytes.copy_from_slice(ss.as_slice());
    Ok((ss_bytes, ct_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TestRng;

    #[test]
    fn encapsulate_then_decapsulate_agrees() {
        let mut rng = TestRng::new(1);
        let epoch = PqEpoch::new(&mut rng);
        let (ss_send, ct) = encapsulate_to(epoch.ek(), &mut rng).expect("valid key");
        let ss_recv = epoch.decapsulate(&ct);
        assert_eq!(ss_send, ss_recv);
        assert_ne!(ss_send, [0u8; 32]);
    }

    #[test]
    fn wrong_epoch_decapsulates_to_a_different_secret() {
        let mut rng = TestRng::new(2);
        let a = PqEpoch::new(&mut rng);
        let b = PqEpoch::new(&mut rng);
        assert_ne!(a.ek(), b.ek());

        let (ss, ct) = encapsulate_to(a.ek(), &mut rng).expect("valid key");
        // Implicit rejection: no error, just a secret nobody else can predict.
        assert_ne!(ss, b.decapsulate(&ct));
    }

    #[test]
    fn tampered_ciphertext_decapsulates_to_a_different_secret() {
        let mut rng = TestRng::new(3);
        let epoch = PqEpoch::new(&mut rng);
        let (ss, mut ct) = encapsulate_to(epoch.ek(), &mut rng).expect("valid key");
        ct[0] ^= 0x01;
        assert_ne!(ss, epoch.decapsulate(&ct));
    }

    #[test]
    fn invalid_encapsulation_key_is_rejected() {
        let mut rng = TestRng::new(4);
        // ML-KEM-768 encapsulation keys carry a modulus check (FIPS 203
        // §7.2): all-0xFF is not a valid encoding.
        let bad = [0xFFu8; ML_KEM_768_EK_LEN];
        assert_eq!(
            encapsulate_to(&bad, &mut rng).unwrap_err(),
            RatchetError::InvalidPqKey
        );
    }

    #[test]
    fn seed_round_trip_reproduces_the_keypair() {
        let mut rng = TestRng::new(5);
        let epoch = PqEpoch::new(&mut rng);
        let (ss, ct) = encapsulate_to(epoch.ek(), &mut rng).expect("valid key");

        let restored = PqEpoch::restore(epoch.seed(), Some(ct));
        assert_eq!(restored.ek(), epoch.ek(), "seed must regenerate the key");
        assert_eq!(
            restored.decapsulate(&ct),
            ss,
            "restored epoch must decapsulate what the original could"
        );
        assert_eq!(restored.pending_ct(), Some(&ct));
    }

    #[test]
    fn fresh_epochs_differ() {
        let mut rng = TestRng::new(6);
        let a = PqEpoch::new(&mut rng);
        let b = PqEpoch::new(&mut rng);
        assert_ne!(a.seed(), b.seed());
        assert_ne!(a.ek(), b.ek());
    }

    #[test]
    fn key_and_ciphertext_lengths_match_ml_kem_768() {
        let mut rng = TestRng::new(7);
        let epoch = PqEpoch::new(&mut rng);
        assert_eq!(epoch.ek().len(), 1184);
        let (_, ct) = encapsulate_to(epoch.ek(), &mut rng).expect("valid key");
        assert_eq!(ct.len(), 1088);
        assert_eq!(epoch.seed().len(), 64);
    }

    #[test]
    fn debug_does_not_leak_the_seed() {
        let mut rng = TestRng::new(8);
        let epoch = PqEpoch::new(&mut rng);
        let rendered = format!("{epoch:?}");
        let seed_hex: String = epoch.seed().iter().map(|b| format!("{b:02x}")).collect();
        assert!(!rendered.contains(&seed_hex));
        assert!(rendered.contains("has_pending_ct"));
    }
}
