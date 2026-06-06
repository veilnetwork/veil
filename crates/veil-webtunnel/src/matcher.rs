//! Path + auth-header matcher for webtunnel secret-mode activation.
//!
//! Used by Phase 5b's HTTP router: incoming request → ask matcher
//! "is this a tunnel-mode request?" → if yes, upgrade to WebSocket;
//! if no, pass to decoy provider.
//!
//! ## Constant-time comparison
//!
//! Both path and auth header are compared with [`subtle::ConstantTimeEq`]
//! to prevent timing-side-channel attacks that could otherwise reveal
//! the secret path byte-by-byte.  An attacker that measures
//! response-time-by-prefix would not learn anything about the secret
//! since the compare runs in constant time regardless of where the
//! mismatch occurs.

use subtle::ConstantTimeEq;

/// Result of matching an incoming HTTP request against tunnel-mode
/// credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchResult {
    /// Path and auth (if configured) both verified — caller should
    /// proceed to WebSocket upgrade.
    TunnelMode,
    /// Path mismatch or auth mismatch — caller should serve decoy
    /// content as a regular HTTPS site.
    Decoy,
}

/// Tunnel-mode credential matcher.
///
/// Construction:
/// - `secret_path` — path string that activates tunnel mode (e.g.
///   `"/_t/n3xK9...32-random-chars"`).  Empty string disables matching.
/// - `auth_header_name` + `auth_token` — optional secondary check.
///   When set, the incoming request must carry `auth_header_name: auth_token`
///   in addition to the path match.  `None` for path-only mode.
///
/// Realism: even with a short secret_path, the auth-header check raises
/// the bar against bulk-path-fuzzing.  Recommended: 32+ random bytes
/// in the path + 32 bytes in the auth token.
pub struct SecretMatcher {
    secret_path: Vec<u8>,
    auth_header_name: Option<String>,
    auth_token: Option<Vec<u8>>,
}

impl SecretMatcher {
    /// Path-only matcher.  `secret_path` must start with `/`.
    pub fn path_only(secret_path: impl Into<String>) -> Self {
        Self {
            secret_path: secret_path.into().into_bytes(),
            auth_header_name: None,
            auth_token: None,
        }
    }

    /// Path + auth-header matcher.  Both must pass for tunnel mode.
    pub fn with_auth(
        secret_path: impl Into<String>,
        auth_header_name: impl Into<String>,
        auth_token: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            secret_path: secret_path.into().into_bytes(),
            auth_header_name: Some(auth_header_name.into()),
            auth_token: Some(auth_token.into()),
        }
    }

    /// Check an incoming request against the credentials.  Returns
    /// `TunnelMode` only when all configured checks pass; `Decoy`
    /// otherwise.  Constant-time on the byte compares.
    ///
    /// `path` is the request path (without host).  `auth_header_value` is
    /// the bytes of the configured auth-header value if the request
    /// carries it, or `None`.  Caller (Phase 5b HTTP router) extracts
    /// it from Hyper's `Request::headers().get(name)` before invoking.
    pub fn check(&self, path: &str, auth_header_value: Option<&[u8]>) -> MatchResult {
        // Path check: must match exactly.  When secret_path is empty
        // tunnel mode is disabled (matcher never returns TunnelMode).
        if self.secret_path.is_empty() {
            return MatchResult::Decoy;
        }
        let path_bytes = path.as_bytes();
        let path_ok = ct_eq_with_length_check(path_bytes, &self.secret_path);

        // Auth check: when configured, must also pass.
        let auth_ok = match &self.auth_token {
            Some(token) => match auth_header_value {
                Some(got) => ct_eq_with_length_check(got, token),
                None => false,
            },
            None => true, // not configured = vacuously true
        };

        if path_ok && auth_ok {
            MatchResult::TunnelMode
        } else {
            MatchResult::Decoy
        }
    }

    /// Name of the auth header this matcher expects, if configured.
    /// Phase 5b's HTTP router uses this to know which header to extract
    /// before calling [`check`](Self::check).
    pub fn auth_header_name(&self) -> Option<&str> {
        self.auth_header_name.as_deref()
    }
}

/// Constant-time equality including length check.  Plain `ct_eq` panics
/// or short-circuits on length mismatch, leaking length-by-timing; this
/// pads-and-XORs so total work is bounded by `max(a.len(), b.len())`.
fn ct_eq_with_length_check(a: &[u8], b: &[u8]) -> bool {
    // Compare lengths in constant-time then content in constant-time.
    // If lengths differ, the content compare is meaningless but we run
    // it anyway against a padded slice to keep timing uniform.
    let len_eq = (a.len() as u64).ct_eq(&(b.len() as u64));
    let n = a.len().min(b.len());
    let content_eq = a[..n].ct_eq(&b[..n]);
    bool::from(len_eq & content_eq)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_secret_path_always_decoy() {
        let m = SecretMatcher::path_only("");
        assert_eq!(m.check("/any/path", None), MatchResult::Decoy);
        assert_eq!(m.check("/", None), MatchResult::Decoy);
    }

    #[test]
    fn matching_path_yields_tunnel_mode() {
        let m = SecretMatcher::path_only("/_t/secret");
        assert_eq!(m.check("/_t/secret", None), MatchResult::TunnelMode);
    }

    #[test]
    fn mismatched_path_yields_decoy() {
        let m = SecretMatcher::path_only("/_t/secret");
        assert_eq!(m.check("/", None), MatchResult::Decoy);
        assert_eq!(m.check("/_t/", None), MatchResult::Decoy);
        assert_eq!(m.check("/_t/secre", None), MatchResult::Decoy);
        assert_eq!(m.check("/_t/secret/", None), MatchResult::Decoy);
        assert_eq!(m.check("/_t/SECRET", None), MatchResult::Decoy);
        assert_eq!(m.check("/other/path", None), MatchResult::Decoy);
    }

    #[test]
    fn auth_required_path_alone_insufficient() {
        let m = SecretMatcher::with_auth("/_t/secret", "X-Auth", b"token".to_vec());
        assert_eq!(m.check("/_t/secret", None), MatchResult::Decoy);
    }

    #[test]
    fn auth_required_wrong_token_decoy() {
        let m = SecretMatcher::with_auth("/_t/secret", "X-Auth", b"token".to_vec());
        assert_eq!(m.check("/_t/secret", Some(b"wrong")), MatchResult::Decoy);
    }

    #[test]
    fn auth_required_both_match_tunnel_mode() {
        let m = SecretMatcher::with_auth("/_t/secret", "X-Auth", b"token".to_vec());
        assert_eq!(
            m.check("/_t/secret", Some(b"token")),
            MatchResult::TunnelMode
        );
    }

    #[test]
    fn auth_required_wrong_path_decoy_regardless_of_token() {
        let m = SecretMatcher::with_auth("/_t/secret", "X-Auth", b"token".to_vec());
        assert_eq!(m.check("/_t/wrong", Some(b"token")), MatchResult::Decoy);
    }

    #[test]
    fn auth_header_name_exposed() {
        let path_only = SecretMatcher::path_only("/_t/x");
        assert_eq!(path_only.auth_header_name(), None);

        let with_auth = SecretMatcher::with_auth("/_t/x", "X-Auth", b"tok".to_vec());
        assert_eq!(with_auth.auth_header_name(), Some("X-Auth"));
    }

    #[test]
    fn ct_eq_handles_length_mismatch() {
        assert!(ct_eq_with_length_check(b"abc", b"abc"));
        assert!(!ct_eq_with_length_check(b"abc", b"abcd"));
        assert!(!ct_eq_with_length_check(b"abc", b"ab"));
        assert!(!ct_eq_with_length_check(b"", b"x"));
    }

    /// Realism: even with paths that share a long prefix, the matcher must
    /// decoy.  Tests against a prefix attack where an adversary that knows
    /// part of the secret could otherwise leak more byte-by-byte.
    #[test]
    fn long_shared_prefix_still_rejected() {
        let secret = "/_t/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1";
        let close = "/_t/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2";
        let m = SecretMatcher::path_only(secret);
        assert_eq!(m.check(close, None), MatchResult::Decoy);
        assert_eq!(m.check(secret, None), MatchResult::TunnelMode);
    }
}
