//! Bootstrap-invite URI encoding.
//!
//! A *bootstrap invite* is a QR / URL handed out-of-band so a brand-new
//! user can join the veil without depending on hardcoded
//! [builtin seeds](super::seeds::builtin_seeds) — which a state-level
//! censor can simply IP-block. The invite carries the minimum a new
//! node needs to dial **one** existing peer; once that handshake
//! succeeds, the rest of the network unfolds via the DHT-walk.
//!
//! Threat model:
//! **Out-of-band channel** (QR scan, signed text message, paper note)
//! is assumed to be uncensored — the operator who hands the invite
//! over is trusted to give a real `(public_key, transport)` pair.
//! **No additional secrecy** is required: anyone who reads the QR
//! gets one peer's address, which is no more sensitive than what the
//! peer already advertises in beacons / DHT.
//! **Replay** is not a concern (no nonce / expiry on the invite
//! itself): the entry just lands in the recipient's
//! `[[bootstrap_peers]]` config, which is one-shot at startup and
//! discarded after the FIND_NODE exchange.
//!
//! Wire format (URL):
//!
//! ```text
//! veil:bootstrap?pk=<b64-pubkey>&t=<endpoint>&a=<algo>&nc=<b64-nonce>[&tls_cert=<b64>][&tls_ca_cert=<b64>]
//! ```
//!
//! Field ordering on **encode** is canonical (`pk → t → a → nc → tls_cert →
//! tls_ca_cert`) so the same `BootstrapPeer` always renders to the same
//! string — important for QR caching and for the "did the operator
//! tamper with this URL" eyeball check. **Decode** accepts arbitrary
//! ordering and is case-sensitive on field names; the scheme prefix is
//! case-insensitive.
//!
//! Mirrors the field set [`veil_types::BootstrapPeer`] one-to-one so
//! `decode_uri(...)` produces a value that can be appended directly to
//! `config.bootstrap_peers`.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use veil_types::{BootstrapPeer, SignatureAlgorithm};

/// Maximum URI length we accept. Generous (4 KiB) — even a Falcon-512
/// public key (~ 900 B base64) plus an XL TLS cert chain fits. Larger
/// payloads almost certainly indicate a malformed pasted URL or an
/// adversarial blob.
pub const MAX_BOOTSTRAP_URI_BYTES: usize = 4 * 1024;

/// Canonical scheme prefix. Distinct from `veil:pair`
/// so a recipient's tooling can route by scheme without ambiguity.
pub const BOOTSTRAP_URI_SCHEME: &str = "veil:bootstrap";

/// Errors emitted by [`decode_uri`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BootstrapUriError {
    #[error("bootstrap uri: oversized ({got}B > {MAX_BOOTSTRAP_URI_BYTES}B)")]
    Oversized { got: usize },
    #[error("bootstrap uri: wrong scheme (expected `{BOOTSTRAP_URI_SCHEME}`)")]
    BadScheme,
    #[error("bootstrap uri: missing `?` query separator")]
    MissingQuery,
    #[error("bootstrap uri: missing required field `{field}`")]
    MissingField { field: &'static str },
    #[error("bootstrap uri: duplicate field `{field}`")]
    DuplicateField { field: &'static str },
    #[error("bootstrap uri: unknown field `{field}`")]
    UnknownField { field: String },
    #[error("bootstrap uri: malformed pair `{pair}` (expected `key=value`)")]
    MalformedPair { pair: String },
    #[error("bootstrap uri: invalid base64 in field `{field}`")]
    InvalidBase64 { field: &'static str },
    #[error("bootstrap uri: unknown algo `{0}` (supported: ed25519, falcon512)")]
    UnknownAlgo(String),
    #[error(
        "bootstrap uri: endpoint `{endpoint}` contains reserved character `{ch}` (forbidden: &, =, ?, #)"
    )]
    EndpointReservedChar { endpoint: String, ch: char },
    #[error("bootstrap uri: endpoint empty")]
    EndpointEmpty,
}

/// Encode a [`BootstrapPeer`] as a canonical `veil:bootstrap?...` URI.
///
/// Returns the URI string. No I/O — pure transform of the in-memory
/// `BootstrapPeer` fields. TLS-cert fields are included only when set
/// to keep the QR small for the common no-TLS case.
pub fn encode_uri(peer: &BootstrapPeer) -> Result<String, BootstrapUriError> {
    validate_endpoint(&peer.transport)?;

    let mut out = String::with_capacity(BOOTSTRAP_URI_SCHEME.len() + 256);
    out.push_str(BOOTSTRAP_URI_SCHEME);
    // Canonical field order (see module doc).
    out.push_str("?pk=");
    out.push_str(&peer.public_key); // already base64 in BootstrapPeer
    out.push_str("&t=");
    out.push_str(&peer.transport);
    out.push_str("&a=");
    out.push_str(algo_to_str(peer.algo));
    out.push_str("&nc=");
    out.push_str(&peer.nonce); // already base64
    if let Some(ref cert) = peer.tls_cert {
        out.push_str("&tls_cert=");
        out.push_str(&URL_SAFE_NO_PAD.encode(cert.as_bytes()));
    }
    if let Some(ref ca) = peer.tls_ca_cert {
        out.push_str("&tls_ca_cert=");
        out.push_str(&URL_SAFE_NO_PAD.encode(ca.as_bytes()));
    }
    Ok(out)
}

/// Parse a canonical bootstrap-invite URI back into a [`BootstrapPeer`].
///
/// Field order is arbitrary; field names are case-sensitive; the
/// `veil:bootstrap` scheme prefix is case-insensitive (browsers
/// lowercase schemes, paper notes might be ALL CAPS). Each field may
/// appear at most once; unknown fields fail decode (forward-compat
/// will introduce versioning if/when needed).
pub fn decode_uri(s: &str) -> Result<BootstrapPeer, BootstrapUriError> {
    if s.len() > MAX_BOOTSTRAP_URI_BYTES {
        return Err(BootstrapUriError::Oversized { got: s.len() });
    }

    let q_idx = s.find('?').ok_or(BootstrapUriError::MissingQuery)?;
    let (head, rest) = s.split_at(q_idx);
    let tail = &rest[1..];

    if !head.eq_ignore_ascii_case(BOOTSTRAP_URI_SCHEME) {
        return Err(BootstrapUriError::BadScheme);
    }

    let mut pk: Option<&str> = None;
    let mut t: Option<&str> = None;
    let mut a: Option<&str> = None;
    let mut nc: Option<&str> = None;
    let mut tls_cert_b64: Option<&str> = None;
    let mut tls_ca_cert_b64: Option<&str> = None;

    for pair in tail.split('&') {
        if pair.is_empty() {
            continue;
        }
        let eq = pair
            .find('=')
            .ok_or_else(|| BootstrapUriError::MalformedPair { pair: pair.into() })?;
        let (key, value_eq) = pair.split_at(eq);
        let value = &value_eq[1..];
        match key {
            "pk" => assign_once(&mut pk, value, "pk")?,
            "t" => assign_once(&mut t, value, "t")?,
            "a" => assign_once(&mut a, value, "a")?,
            "nc" => assign_once(&mut nc, value, "nc")?,
            "tls_cert" => assign_once(&mut tls_cert_b64, value, "tls_cert")?,
            "tls_ca_cert" => assign_once(&mut tls_ca_cert_b64, value, "tls_ca_cert")?,
            other => {
                return Err(BootstrapUriError::UnknownField {
                    field: other.into(),
                });
            }
        }
    }

    let pk = pk.ok_or(BootstrapUriError::MissingField { field: "pk" })?;
    let t = t.ok_or(BootstrapUriError::MissingField { field: "t" })?;
    let a = a.ok_or(BootstrapUriError::MissingField { field: "a" })?;
    let nc = nc.ok_or(BootstrapUriError::MissingField { field: "nc" })?;

    validate_endpoint(t)?;
    let algo = algo_from_str(a)?;
    let tls_cert = tls_cert_b64
        .map(|b| decode_b64_field(b, "tls_cert"))
        .transpose()?;
    let tls_ca_cert = tls_ca_cert_b64
        .map(|b| decode_b64_field(b, "tls_ca_cert"))
        .transpose()?;

    Ok(BootstrapPeer {
        transport: t.to_owned(),
        public_key: pk.to_owned(),
        nonce: nc.to_owned(),
        algo,
        tls_cert,
        tls_ca_cert,
    })
}

// ── helpers ─────────────────────────────────────────────────────────────────

fn assign_once<'a>(
    slot: &mut Option<&'a str>,
    value: &'a str,
    name: &'static str,
) -> Result<(), BootstrapUriError> {
    if slot.is_some() {
        return Err(BootstrapUriError::DuplicateField { field: name });
    }
    *slot = Some(value);
    Ok(())
}

fn algo_to_str(algo: SignatureAlgorithm) -> &'static str {
    match algo {
        SignatureAlgorithm::Ed25519 => "ed25519",
        SignatureAlgorithm::Falcon512 => "falcon512",
        SignatureAlgorithm::Ed25519Falcon512Hybrid => "ed25519+falcon512",
        SignatureAlgorithm::Ed25519Falcon1024Hybrid => "ed25519+falcon1024",
    }
}

fn algo_from_str(s: &str) -> Result<SignatureAlgorithm, BootstrapUriError> {
    match s {
        "ed25519" => Ok(SignatureAlgorithm::Ed25519),
        "falcon512" => Ok(SignatureAlgorithm::Falcon512),
        "ed25519+falcon512" | "hybrid" => Ok(SignatureAlgorithm::Ed25519Falcon512Hybrid),
        "ed25519+falcon1024" | "hybrid1024" => Ok(SignatureAlgorithm::Ed25519Falcon1024Hybrid),
        other => Err(BootstrapUriError::UnknownAlgo(other.to_owned())),
    }
}

fn decode_b64_field(b: &str, name: &'static str) -> Result<String, BootstrapUriError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(b)
        .map_err(|_| BootstrapUriError::InvalidBase64 { field: name })?;
    String::from_utf8(bytes).map_err(|_| BootstrapUriError::InvalidBase64 { field: name })
}

fn validate_endpoint(endpoint: &str) -> Result<(), BootstrapUriError> {
    if endpoint.is_empty() {
        return Err(BootstrapUriError::EndpointEmpty);
    }
    for ch in ['&', '=', '?', '#'] {
        if endpoint.contains(ch) {
            return Err(BootstrapUriError::EndpointReservedChar {
                endpoint: endpoint.to_owned(),
                ch,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_peer() -> BootstrapPeer {
        BootstrapPeer {
            transport: "tcp://10.0.0.1:9000".to_owned(),
            public_key: "abc123def456".to_owned(),
            nonce: "nonce_b64_value".to_owned(),
            algo: SignatureAlgorithm::Ed25519,
            tls_cert: None,
            tls_ca_cert: None,
        }
    }

    #[test]
    fn epic481_1_round_trip_minimal_peer() {
        let p = sample_peer();
        let uri = encode_uri(&p).expect("encode");
        assert!(uri.starts_with("veil:bootstrap?pk="));
        let p2 = decode_uri(&uri).expect("decode");
        assert_eq!(p, p2);
    }

    #[test]
    fn epic481_1_round_trip_with_tls_cert() {
        let mut p = sample_peer();
        p.tls_cert =
            Some("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----".to_owned());
        p.tls_ca_cert = Some("ca-pem-stub".to_owned());
        let uri = encode_uri(&p).expect("encode");
        let p2 = decode_uri(&uri).expect("decode");
        assert_eq!(p, p2);
    }

    #[test]
    fn epic481_1_decode_accepts_arbitrary_field_order() {
        // Reorder: nc → a → t → pk
        let uri =
            "veil:bootstrap?nc=nonce_b64_value&a=ed25519&t=tcp://10.0.0.1:9000&pk=abc123def456";
        let p = decode_uri(uri).expect("decode");
        assert_eq!(p.public_key, "abc123def456");
        assert_eq!(p.transport, "tcp://10.0.0.1:9000");
        assert_eq!(p.nonce, "nonce_b64_value");
        assert_eq!(p.algo, SignatureAlgorithm::Ed25519);
    }

    #[test]
    fn epic481_1_decode_scheme_case_insensitive() {
        let uri = "VEIL:BOOTSTRAP?pk=abc&t=tcp://x:1&a=ed25519&nc=n";
        let p = decode_uri(uri).expect("decode");
        assert_eq!(p.public_key, "abc");
    }

    #[test]
    fn epic481_1_decode_rejects_bad_scheme() {
        let err = decode_uri("veil:pair?pk=x&t=y&a=ed25519&nc=z").unwrap_err();
        assert_eq!(err, BootstrapUriError::BadScheme);
    }

    #[test]
    fn epic481_1_decode_rejects_missing_pk() {
        let err = decode_uri("veil:bootstrap?t=tcp://x:1&a=ed25519&nc=n").unwrap_err();
        assert!(matches!(
            err,
            BootstrapUriError::MissingField { field: "pk" }
        ));
    }

    #[test]
    fn epic481_1_decode_rejects_duplicate_field() {
        let err = decode_uri("veil:bootstrap?pk=a&pk=b&t=tcp://x:1&a=ed25519&nc=n").unwrap_err();
        assert!(matches!(
            err,
            BootstrapUriError::DuplicateField { field: "pk" }
        ));
    }

    #[test]
    fn epic481_1_decode_rejects_unknown_field() {
        let err =
            decode_uri("veil:bootstrap?pk=a&t=tcp://x:1&a=ed25519&nc=n&extra=stuff").unwrap_err();
        assert!(matches!(err, BootstrapUriError::UnknownField { .. }));
    }

    #[test]
    fn epic481_1_decode_rejects_oversized() {
        let big = "veil:bootstrap?pk=".to_string() + &"a".repeat(MAX_BOOTSTRAP_URI_BYTES);
        let err = decode_uri(&big).unwrap_err();
        assert!(matches!(err, BootstrapUriError::Oversized { .. }));
    }

    #[test]
    fn epic481_1_encode_rejects_endpoint_with_reserved_chars() {
        let mut p = sample_peer();
        // Use `&` only — first char in the validator's check order so the
        // failure variant is deterministic regardless of which other
        // reserved chars happen to also appear.
        p.transport = "tcp://x:1&junk".to_owned();
        let err = encode_uri(&p).unwrap_err();
        assert!(
            matches!(err, BootstrapUriError::EndpointReservedChar { ch: '&', .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn epic481_1_decode_rejects_unknown_algo() {
        let err = decode_uri("veil:bootstrap?pk=a&t=tcp://x:1&a=rsa&nc=n").unwrap_err();
        assert!(matches!(err, BootstrapUriError::UnknownAlgo(_)));
    }

    #[test]
    fn epic481_1_canonical_encoding_is_stable() {
        // Re-encode after decode produces the same string for the same input.
        let p = sample_peer();
        let uri1 = encode_uri(&p).unwrap();
        let p2 = decode_uri(&uri1).unwrap();
        let uri2 = encode_uri(&p2).unwrap();
        assert_eq!(uri1, uri2);
    }
}
