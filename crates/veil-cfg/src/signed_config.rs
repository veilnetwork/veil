//! Operator-signed config file (Phase 11 slice 11a).
//!
//! Wraps a TOML config string with an Ed25519 / Falcon-512 signature
//! from the operator's identity keypair.  The signature lives in a
//! single comment-line header at the top of the config file:
//!
//! ```toml
//! # VEIL_CONFIG_SIGNATURE_V1: <base64-blob>
//!
//! [global]
//! ...
//! ```
//!
//! Comment lines are stripped before signing / verifying so that the
//! signed payload is "the TOML without the signature header", letting
//! the operator embed the signature back into the same file.  Multi-
//! line headers are concatenated if the base64 wraps:
//!
//! ```toml
//! # VEIL_CONFIG_SIGNATURE_V1: chunk1
//! # VEIL_CONFIG_SIGNATURE_V1: chunk2
//! ```
//!
//! # Why this matters for production hardening
//!
//! Pre-signing, the config.toml file is a plain text blob lying on
//! the operator's disk.  Anyone with filesystem write access (a container
//! escape, a compromised SSH key, a disgruntled admin) could tamper
//! the config: redirect bootstrap peers to a malicious bundle issuer,
//! flip `legacy_allow_unsigned_bootstrap = true`, lower the rendezvous
//! anycast policy from `signed_only` to `best_effort`, etc.  None of
//! these changes need a daemon restart — the next `node reload` picks
//! them up.
//!
//! Signed configs let operators **pin the trusted config bytes to a
//! known issuer key**.  The daemon refuses to load a signed config
//! that doesn't match the expected pubkey OR has been tampered after
//! signing.  Unsigned configs continue to load but surface a warn so
//! operators see "your config is not signed; tamper protection is off"
//! every startup.
//!
//! # Threat model
//!
//! Defends against:
//! * **Tampered config bytes**: byte-level tamper invalidates the
//!   signature; verification fails.
//! * **Substitute config file**: a wholly attacker-issued config from
//!   a different keypair fails the issuer-pinning check.
//! * **Replay of an old signed config**: `issued_at_unix` is covered
//!   by the signature; loaders can reject configs older than a
//!   freshness window if needed (not enforced here — caller's choice).
//!
//! Does NOT defend against:
//! * **Operator's identity_sk compromise**: rotate the operator
//!   keypair, ship a new signed config.
//! * **Filesystem-level config replacement at daemon startup**: a
//!   container escape that replaces config.toml between filesystem
//!   freeze and daemon read can still bypass verification.  Operators
//!   concerned about this need a full-system signed-boot stack.
//! * **Backward compat — unsigned configs still load**: by design.
//!   Phase 1 enforcement (warn-on-unsigned) gives operators a grace
//!   window to sign their existing configs; phase 2 (refuse-unsigned)
//!   is a separate operator-opt-in flip via a `require_signed_config`
//!   global flag (not shipped in this slice).
//!
//! # Wire format (single envelope, base64-encoded)
//!
//! The base64 blob inside `# VEIL_CONFIG_SIGNATURE_V1:` headers
//! decodes to:
//!
//! ```text
//! [0..2] magic = "SC" (Signed-Config)
//! [2] version = 1
//! [3] issuer_algo u8 (0 = Ed25519, 1 = Falcon-512, 2 = Hybrid)
//! [4..12] issued_at_unix u64 BE
//! [12..14] pk_len u16 BE
//! [14..]    issuer_pk (base64-as-bytes, same encoding as IdentityConfig.public_key)
//! [..2]     sig_len u16 BE
//! [..]      signature (raw bytes)
//! ```
//!
//! # Canonical signed message
//!
//! ```text
//! "veil-signed-config:v1\n"
//! + config_toml_without_signature_headers
//! + "\n"
//! + issued_at_unix.to_string
//! ```
//!
//! Domain prefix prevents cross-protocol signature reuse (a signed
//! bundle signature can't be repurposed as a signed config signature
//! — different `veil-signed-...:v1` prefix).

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use veil_crypto::{sign_message, verify_message};
use veil_types::SignatureAlgorithm;

pub const SIGNED_CONFIG_MAGIC: &[u8; 2] = b"SC";
pub const SIGNED_CONFIG_VERSION: u8 = 1;
pub const SIGNED_CONFIG_DOMAIN_PREFIX: &str = "veil-signed-config:v1\n";
pub const SIGNED_CONFIG_HEADER_PREFIX: &str = "# VEIL_CONFIG_SIGNATURE_V1: ";

/// Hard cap on the issuer pubkey base64 length.  Mirrors the
/// rendezvous-ad cap: Falcon-512 base64 pubkey is ~1196 chars, cap at
/// 2048 for slack and future PQ algos.
pub const MAX_ISSUER_PK_LEN: usize = 2048;
/// Hard cap on the signature raw bytes length.  Same rationale.
pub const MAX_SIGNATURE_LEN: usize = 2048;

#[derive(Debug, thiserror::Error)]
pub enum SignedConfigError {
    #[error(
        "config has no signature header: bytes need a `{SIGNED_CONFIG_HEADER_PREFIX}` line near the top"
    )]
    NoSignatureHeader,
    #[error("config signature header is malformed (base64 decode failed): {0}")]
    BadHeader(String),
    #[error("config signature envelope is malformed: {0}")]
    Malformed(String),
    #[error("unsupported signature algorithm byte: {0}")]
    BadSigAlgo(u8),
    #[error("issuer_pk_len {got} > {MAX_ISSUER_PK_LEN} cap")]
    IssuerPkTooLarge { got: usize },
    #[error("signature_len {got} > {MAX_SIGNATURE_LEN} cap")]
    SignatureTooLarge { got: usize },
    #[error("signature verification failed (wrong key, tampered config, or algorithm mismatch)")]
    Verify,
    #[error("issuer pubkey does not match the pinned expected key")]
    IssuerMismatch,
    #[error("sign: {0}")]
    Sign(String),
    #[error("unsupported version byte: {0} (expected {SIGNED_CONFIG_VERSION})")]
    BadVersion(u8),
}

/// Outcome of [`verify_signed_config`].  Holds the canonical unsigned
/// TOML that caller can pass through to the existing TOML parser, plus
/// the verified envelope metadata.
#[derive(Debug, Clone)]
pub struct VerifiedConfig {
    /// The TOML content WITHOUT the signature header lines — pass this
    /// to the regular `toml::from_str` / `Config` decode path.
    pub unsigned_toml: String,
    /// Issuer pubkey that the signature verified against (base64).
    pub issuer_pk: String,
    /// Signature algorithm that issued the signature.
    pub issuer_algo: SignatureAlgorithm,
    /// Unix timestamp embedded in the signed envelope.  Caller may
    /// enforce a freshness window if needed (this module does not).
    pub issued_at_unix: u64,
}

/// Sign a raw TOML config string and return the **same TOML with the
/// signature header prepended** ready to save back to disk.
///
/// * `content` — the TOML config string to sign.  Should NOT already
///   contain a signature header (it would be stripped and replaced —
///   caller's choice if that's the intent).
/// * `issuer_pk` / `issuer_sk` — the operator's keypair (base64-encoded
///   public key, base64-encoded private key — same encoding as
///   `IdentityConfig`).
/// * `issuer_algo` — must match the keypair.
/// * `issued_at_unix` — unix timestamp embedded in the signed envelope.
pub fn sign_config(
    content: &str,
    issuer_pk: &str,
    issuer_sk: &str,
    issuer_algo: SignatureAlgorithm,
    issued_at_unix: u64,
) -> Result<String, SignedConfigError> {
    if issuer_pk.len() > MAX_ISSUER_PK_LEN {
        return Err(SignedConfigError::IssuerPkTooLarge {
            got: issuer_pk.len(),
        });
    }
    // Step 1: strip any existing signature headers (caller might be
    // re-signing).
    let canonical = strip_signature_headers(content);
    let signed_message = build_signed_message(&canonical, issued_at_unix);

    let signature = sign_message(issuer_algo, issuer_pk, issuer_sk, signed_message.as_bytes())
        .map_err(|e| SignedConfigError::Sign(format!("{e}")))?;
    if signature.len() > MAX_SIGNATURE_LEN {
        return Err(SignedConfigError::SignatureTooLarge {
            got: signature.len(),
        });
    }

    let envelope = encode_envelope(
        issuer_algo,
        issued_at_unix,
        issuer_pk.as_bytes(),
        &signature,
    );
    let envelope_b64 = BASE64.encode(&envelope);

    // Step 2: prepend signature header(s) to the canonical config.  We
    // split the base64 at ~72 chars per line for readability (matches
    // PEM convention; many editors wrap longer lines anyway).
    let header_lines = wrap_envelope_b64(&envelope_b64);
    let mut out = String::with_capacity(content.len() + header_lines.len() * 80);
    for line in header_lines {
        out.push_str(SIGNED_CONFIG_HEADER_PREFIX);
        out.push_str(&line);
        out.push('\n');
    }
    out.push('\n');
    // Use the already-trimmed canonical so the output's body matches
    // what we signed byte-for-byte.  Add a trailing newline so editors
    // that enforce "files end in a newline" don't perturb on save.
    out.push_str(&canonical);
    out.push('\n');
    Ok(out)
}

/// Verify a config file's signature and return the unsigned TOML for
/// the regular Config parser.
///
/// * `content` — the raw TOML file contents (with signature header).
/// * `expected_issuer_pk` — if `Some(pk)`, the signature MUST be issued
///   by this pubkey OR verification fails with `IssuerMismatch`.  If `None`,
///   verification succeeds as long as the envelope is internally
///   consistent (degraded mode — same as `verify_signed_bundle` without
///   a pin; operators concerned about substitution should pin).
pub fn verify_signed_config(
    content: &str,
    expected_issuer_pk: Option<&str>,
) -> Result<VerifiedConfig, SignedConfigError> {
    let envelope_b64 = extract_envelope_b64(content)?;
    let envelope = BASE64
        .decode(envelope_b64.as_bytes())
        .map_err(|e| SignedConfigError::BadHeader(format!("{e}")))?;
    let (issuer_algo, issued_at_unix, issuer_pk, signature) = decode_envelope(&envelope)?;

    if let Some(pinned) = expected_issuer_pk
        && pinned != issuer_pk
    {
        return Err(SignedConfigError::IssuerMismatch);
    }

    let canonical = strip_signature_headers(content);
    let signed_message = build_signed_message(&canonical, issued_at_unix);

    verify_message(
        issuer_algo,
        &issuer_pk,
        signed_message.as_bytes(),
        &signature,
    )
    .map_err(|_| SignedConfigError::Verify)?;

    Ok(VerifiedConfig {
        unsigned_toml: canonical,
        issuer_pk,
        issuer_algo,
        issued_at_unix,
    })
}

/// Quick check: does the content carry a signature header at all?
/// Used by the loader to decide between the verify path and the
/// "unsigned config" warn-and-accept path.
pub fn has_signature_header(content: &str) -> bool {
    content
        .lines()
        .take(50) // signature must be near the top; don't scan whole file
        .any(|line| line.starts_with(SIGNED_CONFIG_HEADER_PREFIX))
}

// ── Internal helpers ──────────────────────────────────────────────

/// Strip lines starting with the signature-header prefix AND normalise
/// edge whitespace.  The result is the canonical TOML that signing /
/// verifying operates on byte-for-byte identically regardless of where
/// the signature header was injected (top of file, blank lines around
/// it, trailing newline differences between editors).
///
/// Trimming edge whitespace is safe because TOML's parsing tolerates
/// leading and trailing whitespace; the operator's actual config bytes
/// between `[section]` markers are preserved verbatim.
pub(crate) fn strip_signature_headers(content: &str) -> String {
    let joined = content
        .lines()
        .filter(|line| !line.starts_with(SIGNED_CONFIG_HEADER_PREFIX))
        .collect::<Vec<_>>()
        .join("\n");
    joined.trim().to_string()
}

fn build_signed_message(canonical: &str, issued_at_unix: u64) -> String {
    let mut msg = String::with_capacity(SIGNED_CONFIG_DOMAIN_PREFIX.len() + canonical.len() + 32);
    msg.push_str(SIGNED_CONFIG_DOMAIN_PREFIX);
    msg.push_str(canonical);
    msg.push('\n');
    msg.push_str(&issued_at_unix.to_string());
    msg
}

fn encode_envelope(
    issuer_algo: SignatureAlgorithm,
    issued_at_unix: u64,
    issuer_pk_bytes: &[u8],
    signature: &[u8],
) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(2 + 1 + 1 + 8 + 2 + issuer_pk_bytes.len() + 2 + signature.len());
    out.extend_from_slice(SIGNED_CONFIG_MAGIC);
    out.push(SIGNED_CONFIG_VERSION);
    out.push(match issuer_algo {
        SignatureAlgorithm::Ed25519 => 0,
        SignatureAlgorithm::Falcon512 => 1,
        SignatureAlgorithm::Ed25519Falcon512Hybrid => 2,
        SignatureAlgorithm::Ed25519Falcon1024Hybrid => 3,
    });
    out.extend_from_slice(&issued_at_unix.to_be_bytes());
    out.extend_from_slice(&(issuer_pk_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(issuer_pk_bytes);
    out.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    out.extend_from_slice(signature);
    out
}

fn decode_envelope(
    buf: &[u8],
) -> Result<(SignatureAlgorithm, u64, String, Vec<u8>), SignedConfigError> {
    let mut p = 0usize;
    if buf.len() < 2 || &buf[..2] != SIGNED_CONFIG_MAGIC {
        return Err(SignedConfigError::Malformed(
            "magic does not match \"SC\"".into(),
        ));
    }
    p += 2;
    if buf.len() < p + 1 {
        return Err(SignedConfigError::Malformed("missing version byte".into()));
    }
    let version = buf[p];
    p += 1;
    if version != SIGNED_CONFIG_VERSION {
        return Err(SignedConfigError::BadVersion(version));
    }
    if buf.len() < p + 1 {
        return Err(SignedConfigError::Malformed("missing algo byte".into()));
    }
    let algo_byte = buf[p];
    p += 1;
    let issuer_algo = match algo_byte {
        0 => SignatureAlgorithm::Ed25519,
        1 => SignatureAlgorithm::Falcon512,
        2 => SignatureAlgorithm::Ed25519Falcon512Hybrid,
        3 => SignatureAlgorithm::Ed25519Falcon1024Hybrid,
        other => return Err(SignedConfigError::BadSigAlgo(other)),
    };
    if buf.len() < p + 8 {
        return Err(SignedConfigError::Malformed("missing issued_at".into()));
    }
    let issued_at_unix = u64::from_be_bytes(buf[p..p + 8].try_into().unwrap());
    p += 8;
    if buf.len() < p + 2 {
        return Err(SignedConfigError::Malformed("missing pk_len".into()));
    }
    let pk_len = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
    p += 2;
    if pk_len > MAX_ISSUER_PK_LEN {
        return Err(SignedConfigError::IssuerPkTooLarge { got: pk_len });
    }
    if buf.len() < p + pk_len {
        return Err(SignedConfigError::Malformed("missing pk bytes".into()));
    }
    let issuer_pk = String::from_utf8(buf[p..p + pk_len].to_vec())
        .map_err(|e| SignedConfigError::Malformed(format!("pk utf8: {e}")))?;
    p += pk_len;
    if buf.len() < p + 2 {
        return Err(SignedConfigError::Malformed("missing sig_len".into()));
    }
    let sig_len = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
    p += 2;
    if sig_len > MAX_SIGNATURE_LEN {
        return Err(SignedConfigError::SignatureTooLarge { got: sig_len });
    }
    if buf.len() < p + sig_len {
        return Err(SignedConfigError::Malformed(
            "missing signature bytes".into(),
        ));
    }
    let signature = buf[p..p + sig_len].to_vec();
    p += sig_len;
    if p != buf.len() {
        return Err(SignedConfigError::Malformed(format!(
            "{} trailing byte(s)",
            buf.len() - p
        )));
    }
    Ok((issuer_algo, issued_at_unix, issuer_pk, signature))
}

/// Extract the concatenated base64 envelope string from signature header
/// lines in the config content.  Multiple header lines are concatenated
/// in order encountered (allows base64 wrapping for long signatures).
fn extract_envelope_b64(content: &str) -> Result<String, SignedConfigError> {
    let mut chunks = Vec::new();
    for line in content.lines().take(50) {
        if let Some(rest) = line.strip_prefix(SIGNED_CONFIG_HEADER_PREFIX) {
            chunks.push(rest.trim().to_string());
        }
    }
    if chunks.is_empty() {
        return Err(SignedConfigError::NoSignatureHeader);
    }
    Ok(chunks.concat())
}

/// Wrap a base64 string at ~72 chars per line for readable storage in
/// the config file.  Matches PEM convention (76 chars without overflow,
/// rounded down to a multiple of 4 for base64-friendly chunking).
fn wrap_envelope_b64(b64: &str) -> Vec<String> {
    const LINE_WIDTH: usize = 72;
    b64.as_bytes()
        .chunks(LINE_WIDTH)
        .map(|chunk| std::str::from_utf8(chunk).unwrap().to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_crypto::generate_keypair;

    fn fixture_config() -> &'static str {
        r#"[global]
node_role = "core"
admin_socket = "unix:///run/veil/admin.sock"

[identity]
public_key = "abc..."
private_key = "xyz..."
"#
    }

    #[test]
    fn sign_then_verify_roundtrip_ed25519() {
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let signed = sign_config(
            fixture_config(),
            &kp.public_key,
            &kp.private_key,
            kp.algo,
            1_700_000_000,
        )
        .unwrap();
        assert!(has_signature_header(&signed));
        let verified = verify_signed_config(&signed, Some(&kp.public_key)).unwrap();
        assert_eq!(verified.issuer_pk, kp.public_key);
        assert_eq!(verified.issued_at_unix, 1_700_000_000);
        assert_eq!(verified.issuer_algo, SignatureAlgorithm::Ed25519);
        // unsigned_toml round-trips to the original (modulo leading
        // whitespace that the sign call trims).
        assert!(verified.unsigned_toml.contains("node_role = \"core\""));
        assert!(!verified.unsigned_toml.contains(SIGNED_CONFIG_HEADER_PREFIX));
    }

    #[test]
    fn verify_rejects_tampered_body() {
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let signed = sign_config(
            fixture_config(),
            &kp.public_key,
            &kp.private_key,
            kp.algo,
            1_700_000_000,
        )
        .unwrap();
        // Tamper: flip "core" to "edge" in the role field — keeps TOML
        // syntactically valid but invalidates the signature.
        let tampered = signed.replace("node_role = \"core\"", "node_role = \"edge\"");
        let err = verify_signed_config(&tampered, Some(&kp.public_key)).unwrap_err();
        assert!(matches!(err, SignedConfigError::Verify));
    }

    #[test]
    fn verify_rejects_wrong_pin() {
        let kp_a = generate_keypair(SignatureAlgorithm::Ed25519);
        let kp_b = generate_keypair(SignatureAlgorithm::Ed25519);
        let signed = sign_config(
            fixture_config(),
            &kp_a.public_key,
            &kp_a.private_key,
            kp_a.algo,
            1_700_000_000,
        )
        .unwrap();
        let err = verify_signed_config(&signed, Some(&kp_b.public_key)).unwrap_err();
        assert!(matches!(err, SignedConfigError::IssuerMismatch));
    }

    #[test]
    fn verify_accepts_unpinned_mode() {
        // No pin → signature integrity only (degraded mode).  Useful
        // when operator distributes the pubkey OOB but does not pin
        // its base64 form in the binary.
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let signed = sign_config(
            fixture_config(),
            &kp.public_key,
            &kp.private_key,
            kp.algo,
            1_700_000_000,
        )
        .unwrap();
        let verified = verify_signed_config(&signed, None).unwrap();
        assert_eq!(verified.issuer_pk, kp.public_key);
    }

    #[test]
    fn verify_rejects_missing_signature_header() {
        // Plain unsigned TOML — verify_signed_config refuses, caller
        // must fall back to the unsigned-load path.
        let err = verify_signed_config(fixture_config(), None).unwrap_err();
        assert!(matches!(err, SignedConfigError::NoSignatureHeader));
    }

    #[test]
    fn has_signature_header_detects_correctly() {
        assert!(!has_signature_header(fixture_config()));
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let signed = sign_config(
            fixture_config(),
            &kp.public_key,
            &kp.private_key,
            kp.algo,
            1_700_000_000,
        )
        .unwrap();
        assert!(has_signature_header(&signed));
    }

    #[test]
    fn cross_protocol_replay_blocked_by_domain_prefix() {
        // Sign a config with timestamp T.  Try to use that signature on
        // a CRAFTED message that omits the domain prefix.  Verify must
        // reject (signature was issued under the prefixed message).
        // This test verifies the domain prefix is actually included in
        // the signed payload.
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let signed = sign_config(
            fixture_config(),
            &kp.public_key,
            &kp.private_key,
            kp.algo,
            1_700_000_000,
        )
        .unwrap();
        // Direct verify using the underlying primitive without the
        // domain prefix MUST fail.  This catches a refactor that
        // forgets to include the prefix.
        let canonical = strip_signature_headers(&signed);
        let no_prefix_message = format!("{canonical}\n{}", 1_700_000_000u64);
        let envelope_b64 = extract_envelope_b64(&signed).unwrap();
        let envelope = BASE64.decode(envelope_b64.as_bytes()).unwrap();
        let (algo, _ts, pk, sig) = decode_envelope(&envelope).unwrap();
        assert!(verify_message(algo, &pk, no_prefix_message.as_bytes(), &sig).is_err());
    }

    #[test]
    fn multi_line_envelope_concatenates() {
        // Long Falcon-512 signatures wrap across multiple `#`-prefixed
        // lines.  Test simulates that by hand-constructing a wrapped
        // header.
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let signed = sign_config(
            fixture_config(),
            &kp.public_key,
            &kp.private_key,
            kp.algo,
            1_700_000_000,
        )
        .unwrap();
        // The sign call already wraps at 72 chars.  Verify it still
        // round-trips even when the base64 spans multiple lines.
        let line_count = signed
            .lines()
            .filter(|l| l.starts_with(SIGNED_CONFIG_HEADER_PREFIX))
            .count();
        assert!(line_count >= 1);
        let verified = verify_signed_config(&signed, Some(&kp.public_key)).unwrap();
        assert_eq!(verified.issuer_pk, kp.public_key);
    }

    #[test]
    fn malformed_envelope_surfaces_structured_error() {
        let bad = format!(
            "{}{}\n\n[global]\nnode_role = \"core\"\n",
            SIGNED_CONFIG_HEADER_PREFIX, "this is not base64 !!!"
        );
        let err = verify_signed_config(&bad, None).unwrap_err();
        assert!(
            matches!(err, SignedConfigError::BadHeader(_)),
            "expected BadHeader, got {err:?}"
        );
    }

    #[test]
    fn version_byte_mismatch_surfaces_structured_error() {
        // Hand-build an envelope with version byte = 99.
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let canonical = strip_signature_headers(fixture_config());
        let msg = build_signed_message(&canonical, 1_700_000_000);
        let sig = sign_message(kp.algo, &kp.public_key, &kp.private_key, msg.as_bytes()).unwrap();
        let mut envelope = encode_envelope(kp.algo, 1_700_000_000, kp.public_key.as_bytes(), &sig);
        envelope[2] = 99; // overwrite version
        let envelope_b64 = BASE64.encode(&envelope);
        let bad = format!(
            "{}{}\n\n[global]\nnode_role = \"core\"\n",
            SIGNED_CONFIG_HEADER_PREFIX, envelope_b64
        );
        let err = verify_signed_config(&bad, None).unwrap_err();
        assert!(
            matches!(err, SignedConfigError::BadVersion(99)),
            "expected BadVersion(99), got {err:?}"
        );
    }
}
