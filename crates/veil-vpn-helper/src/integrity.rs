//! Binding the elevated helper to the request the HOST wrote.
//!
//! The request JSON is staged in the user's own `%TEMP%` — it has to be, the
//! host is unelevated when it writes it — and the helper used to read it by
//! path after UAC returned. Between those two moments the file is writable by
//! every process of that user, and the elevated read is the only thing that
//! gives its contents power: routes, DNS servers and the SOCKS endpoint of an
//! administrator-level tunnel. A same-user process that rewrites `request.json`
//! while the person is looking at the UAC prompt had the elevated helper apply
//! ITS policy (report5 R5-X-03).
//!
//! What cannot be rewritten after the prompt is the elevated process's command
//! line: it is fixed at CreateProcess, and the person confirmed THAT launch.
//! So the host passes the SHA-256 of the exact bytes it wrote, and the helper
//! refuses a request whose bytes hash to anything else. The digest is not a
//! secret — the attacker may read it — it is a value they cannot change.

use sha2::{Digest, Sha256};

/// Lowercase hex SHA-256 of `bytes`.
pub(crate) fn request_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Whether `bytes` are the request the launch was authorized for.
///
/// Case-insensitive on the expected side only — PowerShell and the C shim pass
/// what the host produced, but a hex string that differs only in case is the
/// same value and refusing it would be a bug, not a defence. An `expected` that
/// is not 64 hex characters is refused outright: an empty or truncated argument
/// must never mean "no check".
pub(crate) fn digest_matches(expected: &str, bytes: &[u8]) -> bool {
    if expected.len() != 64 || !expected.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }
    expected.to_ascii_lowercase() == request_digest(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &[u8] = br#"{"hostPid":42,"token":"t"}"#;

    fn digest() -> String {
        request_digest(BODY)
    }

    #[test]
    fn the_bytes_the_host_wrote_are_accepted() {
        assert!(digest_matches(&digest(), BODY));
    }

    #[test]
    fn upper_case_hex_is_the_same_value() {
        assert!(digest_matches(&digest().to_ascii_uppercase(), BODY));
    }

    #[test]
    fn a_rewritten_request_is_refused() {
        // The attack: same length, same shape, different routing policy.
        let tampered = br#"{"hostPid":42,"token":"X"}"#;
        assert_eq!(tampered.len(), BODY.len());
        assert!(!digest_matches(&digest(), tampered));
    }

    #[test]
    fn one_flipped_byte_is_refused() {
        let mut tampered = BODY.to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(!digest_matches(&digest(), &tampered));
    }

    #[test]
    fn a_missing_or_short_expectation_never_means_no_check() {
        // A shim that forgot the argument, or a truncated one, must not be a
        // way to switch the check off.
        for expected in ["", "0", &"a".repeat(63), &"a".repeat(65)] {
            assert!(
                !digest_matches(expected, BODY),
                "{expected:?} was treated as an expectation"
            );
        }
    }

    #[test]
    fn a_non_hex_expectation_of_the_right_length_is_refused() {
        assert!(!digest_matches(&"z".repeat(64), BODY));
    }

    #[test]
    fn the_windows_loader_checks_before_it_parses() {
        // The pure function above proves nothing about whether anything calls
        // it, and `windows.rs` is cfg(windows) so a test cannot run it here.
        // The ORDER is what matters: a check after the parse would already
        // have let a rewritten policy through serde, and a check that is not
        // there at all is the defect this closes.
        let src = include_str!("windows.rs");
        let checked = src
            .find("integrity::digest_matches")
            .expect("the Windows request loader does not check the digest at all");
        let parsed = src
            .find("serde_json::from_slice::<HelperConfig>")
            .expect("the Windows request loader no longer parses HelperConfig here");
        assert!(
            checked < parsed,
            "the request is parsed before it is checked against the approved launch"
        );
    }

    #[test]
    fn the_digest_is_the_standard_one() {
        // Against a value from outside this implementation: sha256("") as
        // every other SHA-256 in the world computes it.
        assert_eq!(
            request_digest(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
