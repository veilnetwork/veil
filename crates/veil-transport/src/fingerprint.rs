//! TLS ClientHello fingerprint profiles + runtime rotation policy.
//!
//! # What this is
//!
//! When the `tls-boring` feature is active, the veil TLS transport emits a
//! ClientHello shaped to match a popular browser so on-path DPI cannot
//! fingerprint (JA3/JA4) and block veil traffic. This module defines the
//! selectable profiles ([`TlsFingerprint`]), the concrete BoringSSL knobs each
//! profile sets ([`FingerprintProfile`]), and the runtime policy
//! ([`TlsFingerprintPolicy`]) that decides which profile to use per connection
//! and how to rotate to another when one stops working.
//!
//! # Why rotation
//!
//! DPI has shifted from blocklisting (block known-bad JA3) to allowlisting
//! (block everything that is not a known-good browser JA3), and operators now
//! accept collateral damage — blocking even Chrome's fingerprint. A single
//! pinned profile therefore loses outright once that profile is banned.
//! Rotation lets a node fall back to a *different real-browser* fingerprint
//! when a handshake fails, so the loss of one JA3 class does not sever
//! connectivity. The [`TlsFingerprintPolicy::record_success`] / sticky logic
//! keeps using the last profile that worked, so steady-state traffic does not
//! thrash through dead fingerprints.
//!
//! # Fidelity (honest scope)
//!
//! All profiles are produced by BoringSSL (the `btls` crate), which is Chrome's
//! own TLS stack — so [`TlsFingerprint::Chrome`] / [`TlsFingerprint::AndroidChrome`]
//! are near-native. Firefox/Safari/iOS are **JA3-class approximations**: their
//! native stacks (NSS / SecureTransport) order the TLS 1.3 cipher suites and
//! some extensions differently, and BoringSSL fixes those, so the bytes are not
//! identical. What differs (and what DPI keys on for the JA3 *class*) is the
//! TLS 1.2 cipher ordering, supported-groups, signature algorithms, GREASE, and
//! extension-permutation — all of which these profiles do vary. BoringSSL also
//! cannot offer FFDHE groups, so Firefox's `ffdhe*` groups are dropped (EC-only).

use std::borrow::Cow;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A selectable ClientHello fingerprint profile.
///
/// `Randomized` is special: it is materialised into a fresh random (but valid)
/// [`FingerprintProfile`] every time it is applied, so two connections using
/// `Randomized` present different ClientHellos.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsFingerprint {
    /// Desktop Chrome (Chromium) — near-native under BoringSSL.
    Chrome,
    /// Desktop Firefox — JA3-class approximation (NSS not byte-reproducible).
    Firefox,
    /// Desktop Safari (macOS) — JA3-class approximation.
    Safari,
    /// Mobile Safari (iOS) — JA3-class approximation.
    IosSafari,
    /// Mobile Chrome (Android) — near-native under BoringSSL.
    AndroidChrome,
    /// Fresh randomised-but-valid ClientHello per connection.
    Randomized,
}

impl TlsFingerprint {
    /// Canonical lowercase token used in config (`[transport.tls_fingerprint]`)
    /// and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            TlsFingerprint::Chrome => "chrome",
            TlsFingerprint::Firefox => "firefox",
            TlsFingerprint::Safari => "safari",
            TlsFingerprint::IosSafari => "ios",
            TlsFingerprint::AndroidChrome => "android",
            TlsFingerprint::Randomized => "random",
        }
    }

    /// Parse a config token into a fingerprint. Accepts a few aliases. Returns
    /// `None` for unknown tokens so the caller can surface a clear config error.
    pub fn parse(token: &str) -> Option<Self> {
        match token.trim().to_ascii_lowercase().as_str() {
            "chrome" => Some(TlsFingerprint::Chrome),
            "firefox" | "ff" => Some(TlsFingerprint::Firefox),
            "safari" => Some(TlsFingerprint::Safari),
            "ios" | "ios_safari" | "ios-safari" => Some(TlsFingerprint::IosSafari),
            "android" | "android_chrome" | "android-chrome" => Some(TlsFingerprint::AndroidChrome),
            "random" | "randomized" | "rand" => Some(TlsFingerprint::Randomized),
            _ => None,
        }
    }

    /// All concrete (non-randomised) browser profiles, in a stable order.
    /// Useful for tests and for documenting the available set.
    pub const ALL_CONCRETE: [TlsFingerprint; 5] = [
        TlsFingerprint::Chrome,
        TlsFingerprint::Firefox,
        TlsFingerprint::Safari,
        TlsFingerprint::IosSafari,
        TlsFingerprint::AndroidChrome,
    ];
}

// ── Concrete BoringSSL knobs per profile ───────────────────────────────────

/// The exact BoringSSL `SslConnectorBuilder` settings that define a ClientHello
/// fingerprint. Built by [`FingerprintProfile::resolve`]; consumed by the
/// `tls-boring` connector builder. Pure data — carries no BoringSSL handle — so
/// the profile table and the rotation logic are unit-testable in default
/// (rustls) builds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FingerprintProfile {
    /// Human label for logs (`chrome`, `random#1`, …).
    pub label: Cow<'static, str>,
    /// TLS 1.2 cipher list in OpenSSL spec form for `set_cipher_list`.
    /// (TLS 1.3 suite order is fixed by BoringSSL and not configurable.)
    pub tls12_ciphers: Cow<'static, str>,
    /// Supported-groups / curves list for `set_curves_list`. EC groups only —
    /// BoringSSL does not support FFDHE groups.
    pub curves: Cow<'static, str>,
    /// Signature-algorithms list for `set_sigalgs_list`.
    pub sigalgs: Cow<'static, str>,
    /// Emit GREASE values (cipher/group/extension) — true for all modern browsers.
    pub grease: bool,
    /// Randomise ClientHello extension order per handshake (`set_permute_extensions`).
    /// Chrome does this since ~v110; Firefox/Safari use a fixed order.
    pub permute_extensions: bool,
}

// Cipher / curve / sigalg specs. Names are the OpenSSL/BoringSSL canonical
// forms; the Chrome set is the one already proven to build (see the historical
// `CHROME_*` consts). Other profiles reorder / extend this known-good set so an
// invalid name cannot slip in — the per-profile build tests under `tls-boring`
// assert every one of these compiles into a connector.

const CHROME_CIPHERS: &str = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA";

const FIREFOX_CIPHERS: &str = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:\
ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA";

const SAFARI_CIPHERS: &str = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:\
ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES256-GCM-SHA384:\
ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305:\
ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:\
AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA:AES128-SHA";

const CHROME_CURVES: &str = "X25519:P-256:P-384";
const FF_SAFARI_CURVES: &str = "X25519:P-256:P-384:P-521";

const CHROME_SIGALGS: &str = "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:\
ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512";

const FIREFOX_SIGALGS: &str = "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:\
rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:\
rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512:ecdsa_sha1:rsa_pkcs1_sha1";

const SAFARI_SIGALGS: &str = "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:\
ecdsa_secp384r1_sha384:ecdsa_sha1:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pkcs1_sha1:\
rsa_pss_rsae_sha512:rsa_pkcs1_sha512";

/// Pool of cipher tokens the randomiser shuffles. Every entry is part of at
/// least one real browser profile above, so a random permutation is still a
/// plausible (and valid) cipher list.
const RANDOM_CIPHER_POOL: [&str; 10] = [
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES256-SHA",
    "ECDHE-RSA-AES256-SHA",
    "AES128-GCM-SHA256",
    "AES256-GCM-SHA384",
];

impl FingerprintProfile {
    /// Resolve a [`TlsFingerprint`] into its concrete BoringSSL knobs.
    /// `Randomized` produces a fresh random profile on each call.
    pub fn resolve(fp: TlsFingerprint) -> FingerprintProfile {
        match fp {
            TlsFingerprint::Chrome => FingerprintProfile {
                label: Cow::Borrowed("chrome"),
                tls12_ciphers: Cow::Borrowed(CHROME_CIPHERS),
                curves: Cow::Borrowed(CHROME_CURVES),
                sigalgs: Cow::Borrowed(CHROME_SIGALGS),
                grease: true,
                permute_extensions: true,
            },
            TlsFingerprint::AndroidChrome => FingerprintProfile {
                label: Cow::Borrowed("android"),
                tls12_ciphers: Cow::Borrowed(CHROME_CIPHERS),
                curves: Cow::Borrowed(CHROME_CURVES),
                sigalgs: Cow::Borrowed(CHROME_SIGALGS),
                grease: true,
                permute_extensions: true,
            },
            TlsFingerprint::Firefox => FingerprintProfile {
                label: Cow::Borrowed("firefox"),
                tls12_ciphers: Cow::Borrowed(FIREFOX_CIPHERS),
                curves: Cow::Borrowed(FF_SAFARI_CURVES),
                sigalgs: Cow::Borrowed(FIREFOX_SIGALGS),
                grease: true,
                permute_extensions: false,
            },
            TlsFingerprint::Safari => FingerprintProfile {
                label: Cow::Borrowed("safari"),
                tls12_ciphers: Cow::Borrowed(SAFARI_CIPHERS),
                curves: Cow::Borrowed(FF_SAFARI_CURVES),
                sigalgs: Cow::Borrowed(SAFARI_SIGALGS),
                grease: true,
                permute_extensions: false,
            },
            TlsFingerprint::IosSafari => FingerprintProfile {
                label: Cow::Borrowed("ios"),
                tls12_ciphers: Cow::Borrowed(SAFARI_CIPHERS),
                curves: Cow::Borrowed(FF_SAFARI_CURVES),
                sigalgs: Cow::Borrowed(SAFARI_SIGALGS),
                grease: true,
                permute_extensions: false,
            },
            TlsFingerprint::Randomized => Self::randomized(),
        }
    }

    /// Build a fresh randomised-but-valid profile: a shuffled non-empty subset
    /// of [`RANDOM_CIPHER_POOL`] (always including an AEAD suite), a shuffled
    /// curve order that always leads with X25519, GREASE on, extension
    /// permutation on. The result is a plausible modern-client ClientHello that
    /// differs per connection.
    pub fn randomized() -> FingerprintProfile {
        use rand::seq::SliceRandom;
        let mut rng = rand::rng();

        // Shuffle the cipher pool, then keep a random-length prefix (>= 4) so
        // the list is varied but still a credible browser-sized set.
        let mut ciphers: Vec<&str> = RANDOM_CIPHER_POOL.to_vec();
        ciphers.shuffle(&mut rng);
        // Guarantee at least one GCM AEAD up front for a valid, modern set.
        if !ciphers
            .first()
            .map(|c| c.contains("GCM") || c.contains("CHACHA20"))
            .unwrap_or(false)
        {
            // find an AEAD and swap it to the front
            if let Some(pos) = ciphers
                .iter()
                .position(|c| c.contains("GCM") || c.contains("CHACHA20"))
            {
                ciphers.swap(0, pos);
            }
        }
        let keep = pick_len(&mut rng, 4, ciphers.len());
        ciphers.truncate(keep);
        let tls12_ciphers = ciphers.join(":");

        // Curve order: X25519 always first (every modern browser does this);
        // shuffle the rest.
        let mut tail = ["P-256", "P-384", "P-521"];
        tail.shuffle(&mut rng);
        let curves = format!("X25519:{}", tail.join(":"));

        FingerprintProfile {
            label: Cow::Borrowed("random"),
            tls12_ciphers: Cow::Owned(tls12_ciphers),
            curves: Cow::Owned(curves),
            // Reuse Chrome's sigalgs — a safe, widely-accepted set.
            sigalgs: Cow::Borrowed(CHROME_SIGALGS),
            grease: true,
            permute_extensions: true,
        }
    }
}

/// Pick a length in `[min, max]` inclusive without pulling in `gen_range`
/// generics (keeps the rand surface tiny). Returns `max` if `min >= max`.
fn pick_len(rng: &mut impl rand::Rng, min: usize, max: usize) -> usize {
    if min >= max {
        return max;
    }
    let span = (max - min + 1) as u32;
    min + (rng.next_u32() % span) as usize
}

// ── Runtime policy + rotation ───────────────────────────────────────────────

/// How the transport selects a fingerprint per connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TlsFingerprintMode {
    /// Always use one fixed profile.
    Pinned(TlsFingerprint),
    /// Try each profile in order until one completes the TLS handshake.
    Rotate(Vec<TlsFingerprint>),
    /// Use a fresh randomised profile; retry with new randomisation on failure.
    Random,
}

/// Number of distinct random profiles to try in [`TlsFingerprintMode::Random`]
/// before giving up on a single connect attempt.
const RANDOM_ATTEMPTS: usize = 3;

/// Runtime fingerprint policy held by the [`crate::TransportContext`]. Cheap to
/// clone (the sticky cursor is shared via `Arc`), so all transport-context
/// clones observe the same "last known-good" profile.
#[derive(Clone, Debug)]
pub struct TlsFingerprintPolicy {
    mode: TlsFingerprintMode,
    /// In `Rotate` mode, keep starting from the last profile that succeeded
    /// rather than always re-probing from the head of the list.
    sticky: bool,
    /// Index (into the `Rotate` list) of the last profile that completed a
    /// handshake. Shared across context clones.
    last_ok: Arc<AtomicUsize>,
}

impl Default for TlsFingerprintPolicy {
    /// The shipped default when `tls-boring` is active: rotate Chrome → Firefox
    /// → Safari, sticky. Chosen because allowlist DPI defeats a single pinned
    /// profile; rotating through real desktop browsers degrades gracefully.
    fn default() -> Self {
        Self::rotate(
            vec![
                TlsFingerprint::Chrome,
                TlsFingerprint::Firefox,
                TlsFingerprint::Safari,
            ],
            true,
        )
    }
}

impl TlsFingerprintPolicy {
    /// Fixed single profile.
    pub fn pinned(fp: TlsFingerprint) -> Self {
        Self {
            mode: TlsFingerprintMode::Pinned(fp),
            sticky: false,
            last_ok: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Rotate through `order`, optionally sticky. An empty `order` falls back to
    /// a single Chrome profile so the policy can never produce zero candidates.
    pub fn rotate(order: Vec<TlsFingerprint>, sticky: bool) -> Self {
        let order = if order.is_empty() {
            vec![TlsFingerprint::Chrome]
        } else {
            order
        };
        Self {
            mode: TlsFingerprintMode::Rotate(order),
            sticky,
            last_ok: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Fresh random profile per connection.
    pub fn random() -> Self {
        Self {
            mode: TlsFingerprintMode::Random,
            sticky: false,
            last_ok: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn mode(&self) -> &TlsFingerprintMode {
        &self.mode
    }

    pub fn is_sticky(&self) -> bool {
        self.sticky
    }

    /// The ordered list of `(rotation_index, fingerprint)` to attempt for one
    /// connect. The `rotation_index` is the position in the original `Rotate`
    /// list (so [`Self::record_success`] is unambiguous); for `Pinned`/`Random`
    /// it is always 0.
    ///
    /// In sticky `Rotate` mode the sequence starts at the last known-good index
    /// and wraps, so a node that found a working profile keeps using it and
    /// only re-probes the others if it later fails.
    pub fn attempt_order(&self) -> Vec<(usize, TlsFingerprint)> {
        match &self.mode {
            TlsFingerprintMode::Pinned(fp) => vec![(0, *fp)],
            TlsFingerprintMode::Random => (0..RANDOM_ATTEMPTS)
                .map(|_| (0, TlsFingerprint::Randomized))
                .collect(),
            TlsFingerprintMode::Rotate(order) => {
                let n = order.len();
                let start = if self.sticky {
                    self.last_ok.load(Ordering::Relaxed) % n
                } else {
                    0
                };
                (0..n)
                    .map(|k| {
                        let idx = (start + k) % n;
                        (idx, order[idx])
                    })
                    .collect()
            }
        }
    }

    /// Record that the profile at `rotation_index` just completed a handshake.
    /// No-op unless sticky `Rotate` mode is active.
    pub fn record_success(&self, rotation_index: usize) {
        if self.sticky && matches!(self.mode, TlsFingerprintMode::Rotate(_)) {
            self.last_ok.store(rotation_index, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_parse_roundtrip_and_aliases() {
        for fp in TlsFingerprint::ALL_CONCRETE {
            assert_eq!(TlsFingerprint::parse(fp.as_str()), Some(fp));
        }
        assert_eq!(
            TlsFingerprint::parse("RANDOM"),
            Some(TlsFingerprint::Randomized)
        );
        assert_eq!(TlsFingerprint::parse("ff"), Some(TlsFingerprint::Firefox));
        assert_eq!(
            TlsFingerprint::parse("ios-safari"),
            Some(TlsFingerprint::IosSafari)
        );
        assert_eq!(TlsFingerprint::parse("nope"), None);
    }

    #[test]
    fn concrete_profiles_have_nonempty_specs_and_x25519_first() {
        for fp in TlsFingerprint::ALL_CONCRETE {
            let p = FingerprintProfile::resolve(fp);
            assert!(!p.tls12_ciphers.is_empty(), "{fp:?} ciphers empty");
            assert!(!p.sigalgs.is_empty(), "{fp:?} sigalgs empty");
            assert!(
                p.curves.starts_with("X25519"),
                "{fp:?} curves must lead with X25519: {}",
                p.curves
            );
        }
    }

    #[test]
    fn chrome_and_android_share_native_wire_shape_but_distinct_labels() {
        let c = FingerprintProfile::resolve(TlsFingerprint::Chrome);
        let a = FingerprintProfile::resolve(TlsFingerprint::AndroidChrome);
        // Same BoringSSL knobs → same on-wire ClientHello (both are Chromium).
        assert_eq!(c.tls12_ciphers, a.tls12_ciphers);
        assert_eq!(c.curves, a.curves);
        assert_eq!(c.sigalgs, a.sigalgs);
        assert_eq!(
            (c.grease, c.permute_extensions),
            (a.grease, a.permute_extensions)
        );
        // …but distinct labels so logs/metrics show which profile was selected.
        assert_ne!(c.label, a.label);
    }

    #[test]
    fn distinct_browser_families_have_distinct_fingerprints() {
        let chrome = FingerprintProfile::resolve(TlsFingerprint::Chrome);
        let firefox = FingerprintProfile::resolve(TlsFingerprint::Firefox);
        let safari = FingerprintProfile::resolve(TlsFingerprint::Safari);
        assert_ne!(chrome, firefox);
        assert_ne!(chrome, safari);
        assert_ne!(firefox, safari);
    }

    #[test]
    fn randomized_is_valid_and_varies() {
        // Always X25519-first, always has an AEAD-ish lead cipher, grease on.
        let a = FingerprintProfile::randomized();
        assert!(a.curves.starts_with("X25519"));
        assert!(a.grease && a.permute_extensions);
        assert!(!a.tls12_ciphers.is_empty());
        let lead = a.tls12_ciphers.split(':').next().unwrap();
        assert!(
            lead.contains("GCM") || lead.contains("CHACHA20"),
            "lead cipher should be AEAD, got {lead}"
        );
        // Over several draws we expect at least two different cipher strings —
        // P(all identical) is negligible given the shuffle + length pick.
        let draws: Vec<String> = (0..8)
            .map(|_| FingerprintProfile::randomized().tls12_ciphers.into_owned())
            .collect();
        assert!(
            draws.iter().any(|d| d != &draws[0]),
            "randomized profiles should vary across draws"
        );
    }

    #[test]
    fn pinned_attempt_order_is_single() {
        let pol = TlsFingerprintPolicy::pinned(TlsFingerprint::Firefox);
        assert_eq!(pol.attempt_order(), vec![(0, TlsFingerprint::Firefox)]);
        // record_success is a no-op for pinned (must not panic).
        pol.record_success(0);
    }

    #[test]
    fn random_mode_yields_multiple_random_attempts() {
        let pol = TlsFingerprintPolicy::random();
        let order = pol.attempt_order();
        assert_eq!(order.len(), RANDOM_ATTEMPTS);
        assert!(
            order
                .iter()
                .all(|(_, fp)| *fp == TlsFingerprint::Randomized)
        );
    }

    #[test]
    fn rotate_covers_all_profiles_once_from_head() {
        let pol = TlsFingerprintPolicy::rotate(
            vec![
                TlsFingerprint::Chrome,
                TlsFingerprint::Firefox,
                TlsFingerprint::Safari,
            ],
            false,
        );
        let order = pol.attempt_order();
        assert_eq!(
            order,
            vec![
                (0, TlsFingerprint::Chrome),
                (1, TlsFingerprint::Firefox),
                (2, TlsFingerprint::Safari),
            ]
        );
    }

    #[test]
    fn sticky_rotate_starts_at_last_known_good_and_wraps() {
        let pol = TlsFingerprintPolicy::rotate(
            vec![
                TlsFingerprint::Chrome,
                TlsFingerprint::Firefox,
                TlsFingerprint::Safari,
            ],
            true,
        );
        // Pretend Safari (index 2) was the last that worked.
        pol.record_success(2);
        let order = pol.attempt_order();
        assert_eq!(
            order,
            vec![
                (2, TlsFingerprint::Safari),
                (0, TlsFingerprint::Chrome),
                (1, TlsFingerprint::Firefox),
            ],
            "sticky sequence must start at last_ok and wrap"
        );
    }

    #[test]
    fn non_sticky_rotate_ignores_recorded_success() {
        let pol = TlsFingerprintPolicy::rotate(
            vec![TlsFingerprint::Chrome, TlsFingerprint::Firefox],
            false,
        );
        pol.record_success(1);
        assert_eq!(
            pol.attempt_order()[0].0,
            0,
            "non-sticky always starts at head"
        );
    }

    #[test]
    fn empty_rotate_list_falls_back_to_chrome() {
        let pol = TlsFingerprintPolicy::rotate(vec![], true);
        assert_eq!(pol.attempt_order(), vec![(0, TlsFingerprint::Chrome)]);
    }

    #[test]
    fn default_policy_is_sticky_desktop_rotation() {
        let pol = TlsFingerprintPolicy::default();
        assert!(pol.is_sticky());
        let fps: Vec<TlsFingerprint> = pol.attempt_order().into_iter().map(|(_, f)| f).collect();
        assert_eq!(
            fps,
            vec![
                TlsFingerprint::Chrome,
                TlsFingerprint::Firefox,
                TlsFingerprint::Safari
            ]
        );
    }
}
