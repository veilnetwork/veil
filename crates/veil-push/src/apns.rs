//! Apple Push Notification service (APNs) dispatcher.
//!
//!.4 P3b. Implements the bare-minimum
//! flow needed to wake an iOS client:
//!
//! 1. Load the operator's APNs Auth Key (`AuthKey_<key_id>.p8`
//!    ECDSA P-256 in PEM).
//! 2. Sign a short-lived JWT (ES256, 1-hour validity) with the.p8
//!    key. Claims: `iss = team_id`, `iat = now`.
//! 3. HTTP/2 POST to
//!    `https://api.push.apple.com/3/device/{device_token_hex}`.
//!    Headers: `authorization: bearer <jwt>`, `apns-topic: <bundle_id>`
//!    `apns-push-type: background`. Body: `{"aps":{"content-available":1}}`
//!    — silent push that wakes the app for ~30 s of background
//!    execution; long enough to fetch from the veil mailbox.
//!
//! ## Token-based vs cert-based auth
//!
//! Token-based (.p8) is the modern path Apple recommends. Single key
//! works for all apps in the team; rotates without redeploying.
//! Cert-based (.p12) is legacy; we don't implement it because adding
//! TLS-client-cert plumbing to reqwest blows the dep budget for what
//! is a sunset auth method.
//!
//! ## Production vs sandbox
//!
//! Two endpoints — `api.push.apple.com` (production builds) and
//! `api.sandbox.push.apple.com` (TestFlight / development builds).
//! Operator selects [`ApnsEnvironment`].

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::{PushDispatcher, PushError, PushProvider, PushToken};

const APNS_PROD_HOST: &str = "https://api.push.apple.com";
const APNS_SANDBOX_HOST: &str = "https://api.sandbox.push.apple.com";
/// APNs JWT validity is up to 1 hour. Refresh 5 minutes early so
/// requests in flight at the boundary don't race.
const TOKEN_REFRESH_LEAD_SECS: u64 = 300;
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);

/// Which APNs environment to push to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApnsEnvironment {
    /// `api.push.apple.com` — apps signed for App Store / production.
    Production,
    /// `api.sandbox.push.apple.com` — TestFlight / Xcode dev builds.
    Sandbox,
}

impl ApnsEnvironment {
    fn host(self) -> &'static str {
        match self {
            Self::Production => APNS_PROD_HOST,
            Self::Sandbox => APNS_SANDBOX_HOST,
        }
    }
}

/// Cached JWT + its expiry instant.
struct CachedJwt {
    bearer: String,
    not_after: Instant,
}

/// APNs HTTP/2 dispatcher. Cheap to clone via `Arc`.
pub struct ApnsDispatcher {
    /// Owner-supplied Apple Developer team id (10-char Apple-assigned).
    team_id: String,
    /// Owner-supplied APNs Auth Key id (10-char, printed on the.p8
    /// download page in the Apple developer console).
    key_id: String,
    /// App bundle id (e.g. `com.example.VeilClient`). Sent as
    /// `apns-topic`.
    bundle_id: String,
    /// PEM-decoded ES256 signing key. Wrapped in EncodingKey so we
    /// don't re-parse on every JWT refresh.
    signing_key: jsonwebtoken::EncodingKey,
    http: reqwest::Client,
    /// Endpoint host (one of the two APNs URLs above).
    host: String,
    jwt_cache: Mutex<Option<CachedJwt>>,
    /// Optional override of the host — production code passes None;
    /// tests inject a wiremock URL.
    host_override: Option<String>,
}

impl ApnsDispatcher {
    /// Construct from the.p8 key contents (PEM bytes).
    pub fn from_p8_pem(
        p8_pem: &str,
        key_id: impl Into<String>,
        team_id: impl Into<String>,
        bundle_id: impl Into<String>,
        environment: ApnsEnvironment,
    ) -> Result<Arc<Self>, PushError> {
        let signing_key = jsonwebtoken::EncodingKey::from_ec_pem(p8_pem.as_bytes())
            .map_err(|e| PushError::InvalidToken(format!(".p8 key parse: {e}")))?;
        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .http2_prior_knowledge()
            .user_agent(concat!("veil-push/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| PushError::Transport(format!("reqwest build: {e}")))?;
        Ok(Arc::new(Self {
            team_id: team_id.into(),
            key_id: key_id.into(),
            bundle_id: bundle_id.into(),
            signing_key,
            http,
            host: environment.host().to_owned(),
            jwt_cache: Mutex::new(None),
            host_override: None,
        }))
    }

    /// Construct from a.p8 key file on disk.
    pub fn from_p8_path(
        path: impl AsRef<std::path::Path>,
        key_id: impl Into<String>,
        team_id: impl Into<String>,
        bundle_id: impl Into<String>,
        environment: ApnsEnvironment,
    ) -> Result<Arc<Self>, PushError> {
        let pem = std::fs::read_to_string(path)
            .map_err(|e| PushError::InvalidToken(format!(".p8 read: {e}")))?;
        Self::from_p8_pem(&pem, key_id, team_id, bundle_id, environment)
    }

    /// **Test helper** — replace the APNs host with a mock-server URL.
    /// Not part of the stable API.
    #[doc(hidden)]
    pub fn with_test_host(mut self, host: String) -> Self {
        self.host_override = Some(host);
        self
    }

    fn host(&self) -> &str {
        self.host_override.as_deref().unwrap_or(&self.host)
    }

    /// Sign a fresh ES256 JWT. `kid = key_id` in header, `iss = team_id`
    /// `iat = now`. Apple requires `iat` > 0 and rejects clocks ≥1h old.
    fn build_jwt(&self) -> Result<String, PushError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| PushError::Transport(format!("clock skew: {e}")))?
            .as_secs();
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(self.key_id.clone());
        let claims = ApnsJwtClaims {
            iss: self.team_id.clone(),
            iat: now,
        };
        jsonwebtoken::encode(&header, &claims, &self.signing_key)
            .map_err(|e| PushError::InvalidToken(format!("APNs JWT sign: {e}")))
    }

    /// Cached JWT, refreshing if missing / near expiry.
    async fn provider_jwt(&self) -> Result<String, PushError> {
        {
            let cache = self.jwt_cache.lock().await;
            if let Some(t) = cache.as_ref()
                && t.not_after > Instant::now() + Duration::from_secs(TOKEN_REFRESH_LEAD_SECS)
            {
                return Ok(t.bearer.clone());
            }
        }
        let mut cache = self.jwt_cache.lock().await;
        if let Some(t) = cache.as_ref()
            && t.not_after > Instant::now() + Duration::from_secs(TOKEN_REFRESH_LEAD_SECS)
        {
            return Ok(t.bearer.clone());
        }
        let jwt = self.build_jwt()?;
        // Apple validates JWT freshness; we mirror their 60-min window
        // and refresh slightly early.
        let not_after = Instant::now() + Duration::from_secs(3600);
        *cache = Some(CachedJwt {
            bearer: jwt.clone(),
            not_after,
        });
        Ok(jwt)
    }
}

#[async_trait]
impl PushDispatcher for ApnsDispatcher {
    async fn dispatch(&self, token: &PushToken, wake_payload: &[u8]) -> Result<(), PushError> {
        if token.provider != PushProvider::Apns {
            return Err(PushError::ProviderNotConfigured(token.provider));
        }
        // APNs device token = 32 bytes, sent as 64-char lowercase hex
        // in the URL path.
        let device_token_hex = bytes_to_lower_hex(&token.token);
        let url = format!("{}/3/device/{}", self.host(), device_token_hex);
        let bearer = self.provider_jwt().await?;
        let body = build_apns_body(wake_payload);
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&bearer)
            .header("apns-topic", &self.bundle_id)
            .header("apns-push-type", "background")
            // Background pushes MUST have priority 5 per Apple's spec;
            // priority 10 is rejected ("BadPriority").
            .header("apns-priority", "5")
            .json(&body)
            .send()
            .await
            .map_err(|e| PushError::Transport(format!("APNs POST: {e}")))?;
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        let body = resp.text().await.unwrap_or_default();
        // Truncate the provider body in error strings (audit cycle-9): these
        // PushError messages are logged, and an APNs/FCM error body can echo the
        // push token or be arbitrarily large. The reason field
        // (e.g. {"reason":"BadDeviceToken"}) fits well within the cap.
        match status.as_u16() {
            // 400/410 with reason BadDeviceToken / Unregistered → permanent.
            400 | 403 | 410 => Err(PushError::InvalidToken(format!(
                "APNs rejected token (HTTP {status}): {body:.256}"
            ))),
            429 => Err(PushError::RateLimited),
            _ => Err(PushError::Transport(format!(
                "APNs POST HTTP {status}: {body:.256}"
            ))),
        }
    }
}

fn bytes_to_lower_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[derive(Debug, Serialize)]
struct ApnsJwtClaims {
    iss: String,
    iat: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct ApnsBody {
    aps: ApnsAps,
    /// Authenticated wake-HMAC payload (Epic 489.10 slice 4.4), base64.
    /// Top-level custom key alongside `aps` (Apple delivers custom keys
    /// verbatim to the app). Omitted when the relay had no envelope to mint
    /// from, keeping the body byte-identical to the legacy
    /// `{"aps":{"content-available":1}}`.
    #[serde(rename = "w", default, skip_serializing_if = "Option::is_none")]
    w: Option<String>,
}

/// Build the APNs payload JSON. When `wake_payload` is non-empty the 72-byte
/// authenticated payload is base64-encoded under top-level key `"w"`; an empty
/// payload preserves the legacy silent-wake body (back-compat).
fn build_apns_body(wake_payload: &[u8]) -> ApnsBody {
    use base64::Engine;
    let w = if wake_payload.is_empty() {
        None
    } else {
        Some(base64::engine::general_purpose::STANDARD.encode(wake_payload))
    };
    ApnsBody {
        aps: ApnsAps {
            content_available: 1,
        },
        w,
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ApnsAps {
    #[serde(rename = "content-available")]
    content_available: u8,
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Test ECDSA P-256 key in.p8 PEM PKCS#8 format. Generated once
    /// for tests via
    /// `openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt`;
    /// not sensitive — never used outside the test harness.
    const TEST_P8_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgqxuNPrLm8UG+aR78\n\
l2ei6ZBxeBOmRGVwWEKekP0+2OOhRANCAAS+f0KqVIFd2VD0Zy+FG1608YvdiMNA\n\
lKjBRO+ydu6R0vPEAIlh9QR1BnGcwfxfRqP3gbLUR8VsQiZeZon89rYA\n\
-----END PRIVATE KEY-----\n";

    fn mk_dispatcher() -> ApnsDispatcher {
        let arc = ApnsDispatcher::from_p8_pem(
            TEST_P8_PEM,
            "FAKEKEY123",
            "FAKETEAM456",
            "com.example.test",
            ApnsEnvironment::Production,
        )
        .unwrap();
        Arc::try_unwrap(arc).unwrap_or_else(|a| (*a).clone_for_test())
    }

    #[cfg(test)]
    impl ApnsDispatcher {
        fn clone_for_test(&self) -> Self {
            Self {
                team_id: self.team_id.clone(),
                key_id: self.key_id.clone(),
                bundle_id: self.bundle_id.clone(),
                signing_key: jsonwebtoken::EncodingKey::from_ec_pem(TEST_P8_PEM.as_bytes())
                    .unwrap(),
                http: self.http.clone(),
                host: self.host.clone(),
                jwt_cache: Mutex::new(None),
                host_override: self.host_override.clone(),
            }
        }
    }

    #[test]
    fn t1_4_p3b_apns_loads_p8_pem() {
        let _d = mk_dispatcher();
    }

    #[test]
    fn t1_4_p3b_apns_rejects_bad_p8() {
        let res = ApnsDispatcher::from_p8_pem(
            "-----BEGIN PRIVATE KEY-----\nNOT A KEY\n-----END PRIVATE KEY-----",
            "k",
            "t",
            "b",
            ApnsEnvironment::Production,
        );
        assert!(matches!(res, Err(PushError::InvalidToken(_))));
    }

    #[test]
    fn t1_4_p3b_apns_jwt_signs_es256() {
        let d = mk_dispatcher();
        let jwt = d.build_jwt().unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        // Decode header to verify alg = ES256 and kid = key_id.
        use base64::Engine;
        let header_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[0])
            .unwrap();
        let header_str = std::str::from_utf8(&header_json).unwrap();
        assert!(header_str.contains("\"alg\":\"ES256\""));
        assert!(header_str.contains("\"kid\":\"FAKEKEY123\""));
    }

    #[test]
    fn t489_10_apns_wake_payload_base64_top_level_w_key() {
        // Epic 489.10 slice 4.4: a non-empty 72-byte wake payload is
        // base64-encoded as a top-level "w" custom key alongside "aps";
        // content-available silent-wake is preserved.
        use base64::Engine;
        let payload = [0xA5u8; 72];
        let body = build_apns_body(&payload);
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["aps"]["content-available"], 1);
        let expected_b64 = base64::engine::general_purpose::STANDARD.encode(payload);
        assert_eq!(json["w"], expected_b64);
        assert_eq!(expected_b64.len(), 96);
    }

    #[test]
    fn t489_10_apns_empty_wake_payload_preserves_wake_only() {
        // Empty payload → body byte-identical to the legacy
        // {"aps":{"content-available":1}}: the top-level "w" key is absent.
        let body = build_apns_body(&[]);
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["aps"]["content-available"], 1);
        assert!(json.get("w").is_none(), "empty payload must omit the w key");
        // Only the "aps" key at top level.
        assert_eq!(json.as_object().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn t1_4_p3b_apns_dispatch_rejects_wrong_provider() {
        let d = mk_dispatcher();
        let fcm_token = PushToken {
            provider: PushProvider::Fcm,
            token: b"x".to_vec(),
        };
        let err = d.dispatch(&fcm_token, &[]).await.unwrap_err();
        assert!(matches!(
            err,
            PushError::ProviderNotConfigured(PushProvider::Fcm)
        ));
    }

    #[tokio::test]
    async fn t1_4_p3b_apns_dispatch_happy_path() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/3/device/[0-9a-f]{64}$"))
            .and(header("apns-topic", "com.example.test"))
            .and(header("apns-push-type", "background"))
            .and(header("apns-priority", "5"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock)
            .await;
        let d = mk_dispatcher().with_test_host(mock.uri());
        let token = PushToken {
            provider: PushProvider::Apns,
            token: vec![0xABu8; 32],
        };
        d.dispatch(&token, &[]).await.unwrap();
    }

    #[tokio::test]
    async fn t1_4_p3b_apns_410_maps_to_invalid_token() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/3/device/.*"))
            .respond_with(
                ResponseTemplate::new(410)
                    .set_body_json(serde_json::json!({"reason": "Unregistered"})),
            )
            .mount(&mock)
            .await;
        let d = mk_dispatcher().with_test_host(mock.uri());
        let token = PushToken {
            provider: PushProvider::Apns,
            token: vec![0u8; 32],
        };
        let err = d.dispatch(&token, &[]).await.unwrap_err();
        assert!(matches!(err, PushError::InvalidToken(_)));
    }

    #[tokio::test]
    async fn t1_4_p3b_apns_429_maps_to_rate_limited() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/3/device/.*"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&mock)
            .await;
        let d = mk_dispatcher().with_test_host(mock.uri());
        let token = PushToken {
            provider: PushProvider::Apns,
            token: vec![0u8; 32],
        };
        let err = d.dispatch(&token, &[]).await.unwrap_err();
        assert!(matches!(err, PushError::RateLimited));
    }

    #[test]
    fn t1_4_p3b_apns_bytes_to_hex() {
        assert_eq!(bytes_to_lower_hex(&[0x00, 0xAB, 0xFF]), "00abff");
        assert_eq!(bytes_to_lower_hex(&[]), "");
    }

    #[test]
    fn t1_4_p3b_apns_environment_hosts() {
        assert_eq!(
            ApnsEnvironment::Production.host(),
            "https://api.push.apple.com"
        );
        assert_eq!(
            ApnsEnvironment::Sandbox.host(),
            "https://api.sandbox.push.apple.com"
        );
    }
}
