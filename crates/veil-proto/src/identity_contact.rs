//! Public-contact payload for QR identity sharing.
//!
//! A sovereign identity is identified by its stable `node_id` and
//! anchored by the `master_pubkey` that hashes to it. When Alice wants
//! to share her identity with Bob she renders these two values (plus an
//! optional preferred name) as a URI that any QR renderer can encode:
//!
//! ```text
//! veil:identity?id=<64-hex-node_id>
//! &master_algo=<ed25519|falcon512>
//! &master_pk=<hex-master-pubkey>
//! [&name=<normalized-name>]
//! ```
//!
//! Bob's scanner parses it back [`IdentityContact::from_uri`] and
//! hands the result to the identity layer, which verifies the binding
//! `node_id == BLAKE3("veil.identity.v1" || len || master_pk)`
//! before storing the contact.
//!
//! # Design notes
//!
//! **No URL crate**. Query-string parsing is a handful of
//! `split('=')` / `split('&')` calls — adding a dependency here
//! would dwarf the code.
//! **No percent-encoding**. `id` and `master_pk` are hex; `name` is
//! restricted to the same ASCII charset as the NameClaim V2
//! normalizer (`[a-z0-9#_-]`) so every character is URI-safe by
//! construction.
//! **Field order doesn't matter on parse** — callers should not rely
//! on it, but we always *emit* a canonical order so signed/QR'd
//! payloads that happen to round-trip are byte-stable.
//! **Case**: the scheme + algo name are compared case-insensitively on
//! parse (`Veil:Identity`, `ED25519` both accepted); we always
//! emit lowercase.
//! **Master pubkey length is algo-defined**: 32 B for Ed25519, 897 B
//! for Falcon-512 (per `MAX_PUBKEY_BYTES` in `identity_document.rs`).
//! Parser enforces the length per algo.
//!
//! The wire-level verifier still enforces the actual
//! `node_id == BLAKE3(master_pubkey)` binding; this module only
//! handles the URI syntax + charset validation.

use crate::identity_document::{ALGO_ED25519, ALGO_FALCON512};
use crate::name_claim_v2;
use veil_util::bytes_to_hex;

// ── Constants ────────────────────────────────────────────────────────────────

/// Canonical URI scheme + path prefix emitted by [`IdentityContact::to_uri`].
pub const IDENTITY_CONTACT_SCHEME: &str = "veil:identity";

/// Algo-name token for Ed25519 master keys in the URI.
pub const ALGO_NAME_ED25519: &str = "ed25519";
/// Algo-name token for Falcon-512 master keys in the URI.
pub const ALGO_NAME_FALCON512: &str = "falcon512";

/// Maximum URI length we accept — defends against DoS via oversized
/// QR payloads. Ed25519 master_pk (64 hex) + 64-hex node_id +
/// fields + short name comfortably fits in 300 B. Falcon-512 bumps
/// master_pk to 1794 hex; 4 KiB leaves generous headroom for future
/// algorithms without opening an unbounded parse vector.
pub const MAX_CONTACT_URI_BYTES: usize = 4 * 1024;

// ── Types ────────────────────────────────────────────────────────────────────

/// Parsed / to-be-rendered identity-contact payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityContact {
    /// Stable 32-byte node_id (binds to master_pubkey).
    pub node_id: [u8; 32],
    /// Master public-key algorithm byte
    /// (matches [`ALGO_ED25519`] / [`ALGO_FALCON512`]).
    pub master_algo: u8,
    /// Master public key bytes. Length is algo-defined.
    pub master_pubkey: Vec<u8>,
    /// Optional preferred display name. Must be normalizable via
    /// [`name_claim_v2::normalize_name`] — the URI layer rejects
    /// names outside that charset at encode + decode time.
    pub name: Option<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ContactUriError {
    #[error("contact uri: oversized ({got}B > {MAX_CONTACT_URI_BYTES}B)")]
    Oversized { got: usize },
    #[error("contact uri: wrong scheme (expected `veil:identity`)")]
    BadScheme,
    #[error("contact uri: missing `?` query separator")]
    MissingQuery,
    #[error("contact uri: missing required field `{field}`")]
    MissingField { field: &'static str },
    #[error("contact uri: duplicate field `{field}`")]
    DuplicateField { field: &'static str },
    #[error("contact uri: unknown field `{field}`")]
    UnknownField { field: String },
    #[error("contact uri: malformed pair `{pair}` (expected `key=value`)")]
    MalformedPair { pair: String },
    #[error("contact uri: field `{field}` has invalid hex")]
    InvalidHex { field: &'static str },
    #[error(
        "contact uri: field `{field}` has wrong length ({got}B, expected {expected}B for algo {algo})"
    )]
    WrongKeyLength {
        field: &'static str,
        algo: u8,
        got: usize,
        expected: usize,
    },
    #[error("contact uri: unknown master_algo `{0}` (expected `ed25519` or `falcon512`)")]
    UnknownAlgo(String),
    #[error("contact uri: name field failed normalization: {0}")]
    InvalidName(String),
}

impl IdentityContact {
    /// Render the contact as a canonical URI suitable for QR
    /// encoding. The output is pure ASCII and contains no bytes that
    /// require percent-escaping.
    ///
    /// Errors only if the `name` field is set to something outside
    /// the NameClaim V2 charset — callers normally pass an
    /// already-normalised name (or `None`).
    pub fn to_uri(&self) -> Result<String, ContactUriError> {
        let algo_name = algo_byte_to_name(self.master_algo).ok_or(ContactUriError::UnknownAlgo(
            format!("{}", self.master_algo),
        ))?;

        if let Some(ref n) = self.name {
            // Re-normalise so a mis-cased or accidentally padded caller
            // input still produces a valid URI (or a clean rejection).
            name_claim_v2::normalize_name(n)
                .map_err(|e| ContactUriError::InvalidName(e.to_string()))?;
        }

        let mut out = String::with_capacity(IDENTITY_CONTACT_SCHEME.len() + 128);
        out.push_str(IDENTITY_CONTACT_SCHEME);
        out.push_str("?id=");
        out.push_str(&bytes_to_hex(&self.node_id));
        out.push_str("&master_algo=");
        out.push_str(algo_name);
        out.push_str("&master_pk=");
        out.push_str(&bytes_to_hex(&self.master_pubkey));
        if let Some(ref n) = self.name {
            out.push_str("&name=");
            let normalized = name_claim_v2::normalize_name(n)
                .map_err(|e| ContactUriError::InvalidName(e.to_string()))?;
            out.push_str(&normalized);
        }
        Ok(out)
    }

    /// Parse a canonical URI into an [`IdentityContact`]. Scheme
    /// comparison is case-insensitive; field names are
    /// case-sensitive; hex values are accepted in either case and
    /// normalised to lowercase in the returned struct.
    ///
    /// Does NOT verify the `node_id == BLAKE3(master_pk)`
    /// binding — that's the identity verifier's job. This layer
    /// only enforces URI syntax + charset + size.
    pub fn from_uri(s: &str) -> Result<Self, ContactUriError> {
        if s.len() > MAX_CONTACT_URI_BYTES {
            return Err(ContactUriError::Oversized { got: s.len() });
        }

        let q_idx = s.find('?').ok_or(ContactUriError::MissingQuery)?;
        let (head, rest) = s.split_at(q_idx);
        let tail = &rest[1..];

        if !head.eq_ignore_ascii_case(IDENTITY_CONTACT_SCHEME) {
            return Err(ContactUriError::BadScheme);
        }

        let mut id_hex: Option<&str> = None;
        let mut algo_str: Option<&str> = None;
        let mut pk_hex: Option<&str> = None;
        let mut name: Option<&str> = None;

        for pair in tail.split('&') {
            if pair.is_empty() {
                continue;
            }
            let eq = pair
                .find('=')
                .ok_or_else(|| ContactUriError::MalformedPair { pair: pair.into() })?;
            let (key, value_eq) = pair.split_at(eq);
            let value = &value_eq[1..];
            match key {
                "id" => {
                    if id_hex.is_some() {
                        return Err(ContactUriError::DuplicateField { field: "id" });
                    }
                    id_hex = Some(value);
                }
                "master_algo" => {
                    if algo_str.is_some() {
                        return Err(ContactUriError::DuplicateField {
                            field: "master_algo",
                        });
                    }
                    algo_str = Some(value);
                }
                "master_pk" => {
                    if pk_hex.is_some() {
                        return Err(ContactUriError::DuplicateField { field: "master_pk" });
                    }
                    pk_hex = Some(value);
                }
                "name" => {
                    if name.is_some() {
                        return Err(ContactUriError::DuplicateField { field: "name" });
                    }
                    name = Some(value);
                }
                other => {
                    return Err(ContactUriError::UnknownField {
                        field: other.into(),
                    });
                }
            }
        }

        let id_hex = id_hex.ok_or(ContactUriError::MissingField { field: "id" })?;
        let algo_str = algo_str.ok_or(ContactUriError::MissingField {
            field: "master_algo",
        })?;
        let pk_hex = pk_hex.ok_or(ContactUriError::MissingField { field: "master_pk" })?;

        let node_id = decode_hex_fixed::<32>(id_hex, "id")?;

        let master_algo = algo_name_to_byte(algo_str)
            .ok_or_else(|| ContactUriError::UnknownAlgo(algo_str.to_ascii_lowercase()))?;

        let master_pubkey = decode_hex_bytes(pk_hex, "master_pk")?;
        let expected_len = master_pk_len_for_algo(master_algo);
        if master_pubkey.len() != expected_len {
            return Err(ContactUriError::WrongKeyLength {
                field: "master_pk",
                algo: master_algo,
                got: master_pubkey.len(),
                expected: expected_len,
            });
        }

        let name = match name {
            Some(n) => Some(
                name_claim_v2::normalize_name(n)
                    .map_err(|e| ContactUriError::InvalidName(e.to_string()))?,
            ),
            None => None,
        };

        Ok(Self {
            node_id,
            master_algo,
            master_pubkey,
            name,
        })
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn algo_byte_to_name(algo: u8) -> Option<&'static str> {
    match algo {
        ALGO_ED25519 => Some(ALGO_NAME_ED25519),
        ALGO_FALCON512 => Some(ALGO_NAME_FALCON512),
        _ => None,
    }
}

fn algo_name_to_byte(s: &str) -> Option<u8> {
    if s.eq_ignore_ascii_case(ALGO_NAME_ED25519) {
        Some(ALGO_ED25519)
    } else if s.eq_ignore_ascii_case(ALGO_NAME_FALCON512) {
        Some(ALGO_FALCON512)
    } else {
        None
    }
}

/// Canonical raw master-pubkey byte length for a given algo. Matches
/// the byte lengths `identity_document.rs` validates at decode time.
fn master_pk_len_for_algo(algo: u8) -> usize {
    match algo {
        ALGO_ED25519 => 32,
        ALGO_FALCON512 => 897,
        _ => 0, // unknown — parser already rejected before reaching here
    }
}

fn decode_hex_fixed<const N: usize>(
    s: &str,
    field: &'static str,
) -> Result<[u8; N], ContactUriError> {
    let bytes = decode_hex_bytes(s, field)?;
    if bytes.len() != N {
        return Err(ContactUriError::WrongKeyLength {
            field,
            algo: 0,
            got: bytes.len(),
            expected: N,
        });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode_hex_bytes(s: &str, field: &'static str) -> Result<Vec<u8>, ContactUriError> {
    // Audit L-2: reject non-ASCII BEFORE byte-index-slicing the &str below. A
    // multibyte UTF-8 char (from an attacker-supplied contact URI / QR scan)
    // whose bytes straddle a 2-byte slice boundary would otherwise panic
    // ("byte index N is not a char boundary"). Hex is ASCII, so any non-ASCII
    // input is invalid regardless; over ASCII, byte indices are char boundaries.
    if !s.is_ascii() {
        return Err(ContactUriError::InvalidHex { field });
    }
    if !s.len().is_multiple_of(2) {
        return Err(ContactUriError::InvalidHex { field });
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let pair = &s[i..i + 2];
        let byte =
            u8::from_str_radix(pair, 16).map_err(|_| ContactUriError::InvalidHex { field })?;
        out.push(byte);
    }
    Ok(out)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Audit L-2: a hex field with a multibyte-UTF-8 char (from an attacker
    /// contact URI) must return Err, NOT panic on a non-char-boundary slice.
    #[test]
    fn decode_hex_bytes_rejects_multibyte_without_panic_l2() {
        let s = format!("{}\u{20AC}", "a".repeat(61)); // 64 bytes
        assert_eq!(s.len(), 64);
        assert!(decode_hex_bytes(&s, "id").is_err());
    }

    fn sample_ed25519_contact() -> IdentityContact {
        IdentityContact {
            node_id: [0x11; 32],
            master_algo: ALGO_ED25519,
            master_pubkey: vec![0x22; 32],
            name: None,
        }
    }

    fn sample_named_contact() -> IdentityContact {
        IdentityContact {
            node_id: [0xAB; 32],
            master_algo: ALGO_ED25519,
            master_pubkey: vec![0xCD; 32],
            name: Some("alice".into()),
        }
    }

    #[test]
    fn ed25519_roundtrip() {
        let c = sample_ed25519_contact();
        let uri = c.to_uri().unwrap();
        assert!(uri.starts_with("veil:identity?"));
        assert!(uri.contains("master_algo=ed25519"));
        let back = IdentityContact::from_uri(&uri).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn named_contact_roundtrip() {
        let c = sample_named_contact();
        let uri = c.to_uri().unwrap();
        assert!(uri.contains("&name=alice"));
        let back = IdentityContact::from_uri(&uri).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn falcon512_roundtrip() {
        let c = IdentityContact {
            node_id: [0x01; 32],
            master_algo: ALGO_FALCON512,
            master_pubkey: vec![0x02; 897],
            name: None,
        };
        let uri = c.to_uri().unwrap();
        assert!(uri.contains("master_algo=falcon512"));
        assert_eq!(IdentityContact::from_uri(&uri).unwrap(), c);
    }

    #[test]
    fn canonical_field_order_is_stable() {
        let c = sample_named_contact();
        let u1 = c.to_uri().unwrap();
        let u2 = c.to_uri().unwrap();
        assert_eq!(u1, u2);
        // Canonical order is id, master_algo, master_pk (name).
        let id_pos = u1.find("id=").unwrap();
        let algo_pos = u1.find("master_algo=").unwrap();
        let pk_pos = u1.find("master_pk=").unwrap();
        let name_pos = u1.find("name=").unwrap();
        assert!(id_pos < algo_pos);
        assert!(algo_pos < pk_pos);
        assert!(pk_pos < name_pos);
    }

    #[test]
    fn scheme_is_case_insensitive_on_parse() {
        let c = sample_ed25519_contact();
        let uri = c.to_uri().unwrap();
        let upper_scheme = uri.replacen("veil:identity", "Veil:Identity", 1);
        assert_eq!(IdentityContact::from_uri(&upper_scheme).unwrap(), c);
    }

    #[test]
    fn algo_name_is_case_insensitive_on_parse() {
        let c = sample_ed25519_contact();
        let uri = c.to_uri().unwrap().replacen("ed25519", "ED25519", 1);
        assert_eq!(IdentityContact::from_uri(&uri).unwrap(), c);
    }

    #[test]
    fn hex_is_case_insensitive_on_parse() {
        let c = sample_ed25519_contact();
        let uri = c
            .to_uri()
            .unwrap()
            .to_ascii_uppercase()
            .replacen("VEIL:IDENTITY", "veil:identity", 1)
            .replacen("MASTER_ALGO", "master_algo", 1)
            .replacen("ED25519", "ed25519", 1)
            .replacen("MASTER_PK", "master_pk", 1)
            .replacen("ID=", "id=", 1);
        // Uppercase hex still parses to the same bytes.
        let back = IdentityContact::from_uri(&uri).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn field_order_does_not_matter_on_parse() {
        let c = sample_named_contact();
        let hex_id = bytes_to_hex(&c.node_id);
        let hex_pk = bytes_to_hex(&c.master_pubkey);
        let shuffled =
            format!("veil:identity?name=alice&master_pk={hex_pk}&id={hex_id}&master_algo=ed25519");
        assert_eq!(IdentityContact::from_uri(&shuffled).unwrap(), c);
    }

    #[test]
    fn missing_required_field_is_rejected() {
        let err = IdentityContact::from_uri("veil:identity?master_algo=ed25519&master_pk=22")
            .unwrap_err();
        assert!(
            matches!(err, ContactUriError::MissingField { field: "id" }),
            "{err:?}"
        );
    }

    #[test]
    fn bad_scheme_is_rejected() {
        let err = IdentityContact::from_uri("mailto:alice?id=11").unwrap_err();
        assert!(matches!(err, ContactUriError::BadScheme), "{err:?}");
    }

    #[test]
    fn missing_query_is_rejected() {
        let err = IdentityContact::from_uri("veil:identity").unwrap_err();
        assert!(matches!(err, ContactUriError::MissingQuery), "{err:?}");
    }

    #[test]
    fn duplicate_field_is_rejected() {
        let err =
            IdentityContact::from_uri("veil:identity?id=11&id=22&master_algo=ed25519&master_pk=22")
                .unwrap_err();
        assert!(
            matches!(err, ContactUriError::DuplicateField { field: "id" }),
            "{err:?}"
        );
    }

    #[test]
    fn unknown_field_is_rejected() {
        let c = sample_ed25519_contact();
        let uri = format!("{}&mystery=1", c.to_uri().unwrap());
        let err = IdentityContact::from_uri(&uri).unwrap_err();
        assert!(
            matches!(err, ContactUriError::UnknownField { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn malformed_pair_is_rejected() {
        let c = sample_ed25519_contact();
        // Inject a key with no `=` value.
        let uri = format!("{}&bare", c.to_uri().unwrap());
        let err = IdentityContact::from_uri(&uri).unwrap_err();
        assert!(
            matches!(err, ContactUriError::MalformedPair { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn invalid_hex_is_rejected() {
        let err = IdentityContact::from_uri("veil:identity?id=ZZ&master_algo=ed25519&master_pk=22")
            .unwrap_err();
        assert!(matches!(err, ContactUriError::InvalidHex { .. }), "{err:?}");
    }

    #[test]
    fn wrong_node_id_length_is_rejected() {
        let err =
            IdentityContact::from_uri("veil:identity?id=1111&master_algo=ed25519&master_pk=22")
                .unwrap_err();
        assert!(
            matches!(err, ContactUriError::WrongKeyLength { field: "id", .. }),
            "{err:?}"
        );
    }

    #[test]
    fn wrong_master_pk_length_for_algo_is_rejected() {
        let short_pk = bytes_to_hex(&[0xAA; 16]);
        let id = bytes_to_hex(&[0x11; 32]);
        let uri = format!("veil:identity?id={id}&master_algo=ed25519&master_pk={short_pk}");
        let err = IdentityContact::from_uri(&uri).unwrap_err();
        assert!(
            matches!(
                err,
                ContactUriError::WrongKeyLength {
                    field: "master_pk",
                    got: 16,
                    expected: 32,
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn unknown_algo_is_rejected() {
        let id = bytes_to_hex(&[0x11; 32]);
        let uri = format!("veil:identity?id={id}&master_algo=rsa&master_pk=22");
        let err = IdentityContact::from_uri(&uri).unwrap_err();
        assert!(matches!(err, ContactUriError::UnknownAlgo(_)), "{err:?}");
    }

    #[test]
    fn oversized_uri_is_rejected() {
        let big = "veil:identity?".to_string() + &"a=1&".repeat(MAX_CONTACT_URI_BYTES);
        let err = IdentityContact::from_uri(&big).unwrap_err();
        assert!(matches!(err, ContactUriError::Oversized { .. }), "{err:?}");
    }

    #[test]
    fn non_normalizable_name_is_rejected() {
        let id = bytes_to_hex(&[0x11; 32]);
        let pk = bytes_to_hex(&[0x22; 32]);
        let uri = format!("veil:identity?id={id}&master_algo=ed25519&master_pk={pk}&name=alíce");
        let err = IdentityContact::from_uri(&uri).unwrap_err();
        assert!(matches!(err, ContactUriError::InvalidName(_)), "{err:?}");
    }

    #[test]
    fn encode_rejects_non_normalizable_name() {
        let mut c = sample_ed25519_contact();
        c.name = Some("alíce".into());
        let err = c.to_uri().unwrap_err();
        assert!(matches!(err, ContactUriError::InvalidName(_)), "{err:?}");
    }

    #[test]
    fn name_is_normalized_on_parse() {
        // Canonical name normalization lower-cases.
        let id = bytes_to_hex(&[0x11; 32]);
        let pk = bytes_to_hex(&[0x22; 32]);
        let uri = format!("veil:identity?id={id}&master_algo=ed25519&master_pk={pk}&name=Alice");
        let parsed = IdentityContact::from_uri(&uri).unwrap();
        assert_eq!(parsed.name.as_deref(), Some("alice"));
    }

    // extraction: `uri_roundtrips_against_a_real_identity_document`
    // moved to `veilcore/tests/identity_contact_roundtrip.rs` because it
    // requires `cfg::sovereign_flow::create_identity` + `crypto::compute_node_id`
    // which live in upper layers and would create a reverse-dep if kept here.
}
