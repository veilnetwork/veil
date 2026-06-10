//! Firebase Cloud Messaging v1 dispatcher.
//!
//!.4 P3b. Implements the bare-minimum
//! flow needed to wake an Android client:
//!
//! 1. Load Google service-account JSON (project_id, client_email
//!    private_key in PEM).
//! 2. Sign a short-lived JWT (RS256, 1-hour expiry) with the service
//!    account's private key, scoped to
//!    `https://www.googleapis.com/auth/firebase.messaging`.
//! 3. Exchange the JWT for an OAuth2 access token at
//!    `https://oauth2.googleapis.com/token`. Cache the token in
//!    memory until a few minutes before its expiry.
//! 4. POST a data-only push to
//!    `https://fcm.googleapis.com/v1/projects/{project_id}/messages:send`.
//!    Data-only (no `notification` field) keeps the push silent — the
//!    Android client wakes, fetches new messages from the veil
//!    mailbox, and stays in foreground only as long as needed.
//!
//! ## What this module does NOT do
//!
//! **No retry** on transient HTTP failures. The runtime push task
//! logs and moves on — peer-sync (P4) will retransmit if the wake
//! was missed. Adding a retry loop here risks hammering Google
//! when their backend is degraded.
//! **No batched send.** Each `dispatch` call is one HTTP round-trip.
//! FCM v1 supports batch via separate `:sendMulti` endpoint, but the
//! trigger flow is naturally one-blob-one-push.
//! **No analytics / collapse keys / TTL.** The wake-up payload is a
//! single `{"data":{"wake":"1"}}` — receiver app fetches state from
//! veil mailbox after waking; FCM payload is just the kick.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::{PushDispatcher, PushError, PushProvider, PushToken};

const FCM_OAUTH_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
const FCM_API_BASE: &str = "https://fcm.googleapis.com/v1/projects";
/// Refresh the access token this many seconds before its claimed expiry.
/// Google issues 1-hour tokens; we refresh 5 minutes early so a request
/// in flight at the boundary doesn't race the refresh.
const TOKEN_REFRESH_LEAD_SECS: u64 = 300;
/// Upper cap on the OAuth `expires_in` we will honor. Google issues
/// 1-hour tokens; cap at 2 hours so a buggy/compromised OAuth response
/// claiming `expires_in = u64::MAX` cannot turn the cache into a
/// revocation oracle that never refreshes (M-22).
const MAX_TOKEN_LIFETIME_SECS: u64 = 7200;
/// Lower cap on `expires_in` so a degenerate response cannot make us
/// hammer the OAuth endpoint on every dispatch.
const MIN_TOKEN_LIFETIME_SECS: u64 = 60;
/// Hard cap on a single HTTP request — both OAuth exchange and FCM send.
/// Long enough for slow networks but bounded so a stuck connection
/// doesn't pile up triggers in the mpsc.
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);

/// Service-account JSON shape (subset). Mirrors Google's exact field
/// names so we can `serde_json::from_str` directly.
#[derive(Debug, Clone, Deserialize)]
struct ServiceAccount {
    /// Cloud project id (used in the FCM endpoint path).
    project_id: String,
    /// Service-account email — also the JWT issuer claim.
    client_email: String,
    /// Private key in PEM ("-----BEGIN PRIVATE KEY-----..."), RSA-2048.
    private_key: String,
}

/// Cached OAuth2 access token + its expiry instant.
struct CachedToken {
    bearer: String,
    not_after: Instant,
}

/// FCM v1 dispatcher. Cheap to clone via `Arc`.
pub struct FcmDispatcher {
    service_account: ServiceAccount,
    http: reqwest::Client,
    /// Endpoint URL pre-built at construction so each dispatch
    /// doesn't re-format. Embeds the project_id.
    send_url: String,
    /// In-memory token cache. `Mutex` (not `RwLock`) because contention
    /// is low and the refresh path requires write access; using one
    /// lock keeps the code simple.
    token_cache: Mutex<Option<CachedToken>>,
    /// Optional override of the OAuth2 endpoint — production code uses
    /// the constant; tests inject a wiremock URL. `None` = use Google's
    /// real endpoint.
    oauth_url_override: Option<String>,
    /// Optional override of the FCM send endpoint base — same rationale.
    send_url_override: Option<String>,
}

impl FcmDispatcher {
    /// Construct from a service-account JSON blob (the file contents
    /// not the path). Useful when the operator stores credentials in
    /// a secret manager and wants to feed bytes directly.
    pub fn from_service_account_json(json: &str) -> Result<Arc<Self>, PushError> {
        let sa: ServiceAccount = serde_json::from_str(json).map_err(|e| {
            PushError::InvalidToken(format!("service-account JSON parse failed: {e}"))
        })?;
        let send_url = format!("{}/{}/messages:send", FCM_API_BASE, sa.project_id);
        let http = reqwest::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .user_agent(concat!("veil-push/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| PushError::Transport(format!("reqwest build: {e}")))?;
        Ok(Arc::new(Self {
            service_account: sa,
            http,
            send_url,
            token_cache: Mutex::new(None),
            oauth_url_override: None,
            send_url_override: None,
        }))
    }

    /// Construct from a service-account JSON file on disk.
    pub fn from_service_account_path(
        path: impl AsRef<std::path::Path>,
    ) -> Result<Arc<Self>, PushError> {
        let bytes = std::fs::read_to_string(path)
            .map_err(|e| PushError::InvalidToken(format!("service-account read: {e}")))?;
        Self::from_service_account_json(&bytes)
    }

    /// **Test helper** — replace the OAuth + send URLs with mock-server
    /// equivalents. Not part of the stable API.
    #[doc(hidden)]
    pub fn with_test_endpoints(
        mut self,
        oauth_url: Option<String>,
        send_url: Option<String>,
    ) -> Self {
        self.oauth_url_override = oauth_url;
        self.send_url_override = send_url;
        self
    }

    fn oauth_url(&self) -> &str {
        self.oauth_url_override
            .as_deref()
            .unwrap_or(FCM_OAUTH_TOKEN_URL)
    }

    fn send_url(&self) -> &str {
        self.send_url_override.as_deref().unwrap_or(&self.send_url)
    }

    /// Build a fresh JWT signed with the service-account's RSA key
    /// scoped to firebase.messaging. `iat = now`, `exp = now + 3600`.
    fn build_jwt(&self) -> Result<String, PushError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| PushError::Transport(format!("clock skew: {e}")))?
            .as_secs();
        let claims = JwtClaims {
            iss: self.service_account.client_email.clone(),
            scope: FCM_SCOPE.to_owned(),
            aud: FCM_OAUTH_TOKEN_URL.to_owned(),
            iat: now,
            exp: now + 3600,
        };
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        let key =
            jsonwebtoken::EncodingKey::from_rsa_pem(self.service_account.private_key.as_bytes())
                .map_err(|e| PushError::InvalidToken(format!("RSA key parse: {e}")))?;
        jsonwebtoken::encode(&header, &claims, &key)
            .map_err(|e| PushError::InvalidToken(format!("JWT sign: {e}")))
    }

    /// Return a cached bearer token, refreshing if missing / near expiry.
    async fn access_token(&self) -> Result<String, PushError> {
        {
            let cache = self.token_cache.lock().await;
            if let Some(t) = cache.as_ref()
                && t.not_after > Instant::now() + Duration::from_secs(TOKEN_REFRESH_LEAD_SECS)
            {
                return Ok(t.bearer.clone());
            }
        }
        // Slow path: refresh under the same mutex so concurrent
        // dispatches don't double-fetch.
        let mut cache = self.token_cache.lock().await;
        // Re-check inside the lock — another caller may have refreshed.
        if let Some(t) = cache.as_ref()
            && t.not_after > Instant::now() + Duration::from_secs(TOKEN_REFRESH_LEAD_SECS)
        {
            return Ok(t.bearer.clone());
        }
        let jwt = self.build_jwt()?;
        let resp = self
            .http
            .post(self.oauth_url())
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &jwt),
            ])
            .send()
            .await
            .map_err(|e| PushError::Transport(format!("oauth POST: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(PushError::Transport(format!(
                "oauth refused: HTTP {status} body={body:.256}"
            )));
        }
        let parsed: OAuthResponse = resp
            .json()
            .await
            .map_err(|e| PushError::Transport(format!("oauth response parse: {e}")))?;
        let bearer = parsed.access_token;
        let lifetime = parsed
            .expires_in
            .clamp(MIN_TOKEN_LIFETIME_SECS, MAX_TOKEN_LIFETIME_SECS);
        let not_after = Instant::now() + Duration::from_secs(lifetime);
        *cache = Some(CachedToken {
            bearer: bearer.clone(),
            not_after,
        });
        Ok(bearer)
    }
}

#[async_trait]
impl PushDispatcher for FcmDispatcher {
    async fn dispatch(&self, token: &PushToken, wake_payload: &[u8]) -> Result<(), PushError> {
        if token.provider != PushProvider::Fcm {
            return Err(PushError::ProviderNotConfigured(token.provider));
        }
        let token_str = std::str::from_utf8(&token.token)
            .map_err(|e| PushError::InvalidToken(format!("FCM token not UTF-8: {e}")))?;
        let bearer = self.access_token().await?;
        let body = SendRequest {
            message: SendMessage {
                token: token_str.to_owned(),
                data: build_wake_data(wake_payload),
            },
        };
        let resp = self
            .http
            .post(self.send_url())
            .bearer_auth(&bearer)
            .json(&body)
            .send()
            .await
            .map_err(|e| PushError::Transport(format!("FCM send: {e}")))?;
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        // 401 → token invalid (revoked). Permanent.
        // 404 → registration token unregistered (app uninstalled). Permanent.
        // 429 → quota exceeded. Transient.
        // 5xx → backend trouble. Transient.
        let body = resp.text().await.unwrap_or_default();
        // Truncate the provider body in logged error strings (audit cycle-9):
        // an FCM error body can echo the registration token or be large.
        match status.as_u16() {
            401 | 403 | 404 => Err(PushError::InvalidToken(format!(
                "FCM rejected token (HTTP {status}): {body:.256}"
            ))),
            429 => Err(PushError::RateLimited),
            _ => Err(PushError::Transport(format!(
                "FCM send HTTP {status}: {body:.256}"
            ))),
        }
    }
}

#[derive(Debug, Serialize)]
struct JwtClaims {
    iss: String,
    scope: String,
    aud: String,
    iat: u64,
    exp: u64,
}

#[derive(Debug, Deserialize)]
struct OAuthResponse {
    access_token: String,
    expires_in: u64,
}

#[derive(Debug, Serialize)]
struct SendRequest {
    message: SendMessage,
}

#[derive(Debug, Serialize)]
struct SendMessage {
    token: String,
    data: WakeData,
}

#[derive(Debug, Serialize)]
struct WakeData {
    /// Legacy wake kick — always `"1"` so pre-489.10 receivers (that only
    /// look at `wake`) keep working.
    wake: String,
    /// Authenticated wake-HMAC payload (Epic 489.10 slice 4.4), base64.
    /// Omitted entirely when the relay had no envelope to mint from, which
    /// keeps the on-wire body byte-identical to the legacy `{"wake":"1"}`.
    #[serde(rename = "w", skip_serializing_if = "Option::is_none")]
    w: Option<String>,
}

/// Build the FCM `message.data` map. When `wake_payload` is non-empty the
/// 72-byte authenticated payload is base64-encoded under key `"w"`; an empty
/// payload preserves the legacy wake-only `{"wake":"1"}` body (back-compat).
fn build_wake_data(wake_payload: &[u8]) -> WakeData {
    use base64::Engine;
    let w = if wake_payload.is_empty() {
        None
    } else {
        Some(base64::engine::general_purpose::STANDARD.encode(wake_payload))
    };
    WakeData {
        wake: "1".to_owned(),
        w,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Generate a fake RSA-2048 PEM service-account JSON for tests.
    /// Uses a hard-coded key from `jsonwebtoken`'s own test fixtures
    /// shape — sufficient to exercise our JWT signing path without
    /// pulling a fresh key per run.
    fn fake_service_account_json() -> String {
        // RSA-2048 test key (PEM PKCS#8). Generated once for tests
        // via `openssl genrsa 2048 | openssl pkcs8 -topk8 -nocrypt`;
        // not sensitive — never used outside the test harness.
        const TEST_RSA_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCnaTHG+G2tf5yZ\n\
vV9XzMhKpQ6GFL10c/2Y5mKD7KA3oawiCYx08nn7Hoyyc2BtjsahW/SI9204vwiz\n\
5jTJL1i71fQ0eKOYmaYbjQlYMWqNENvsC+LsonuJq3MU5DZzwGjEUjOIcY1AUHLO\n\
yB7Ij0us8TWpwYEl0/njuY32Sh7LEQED7mflmuBwjrcI6B3PaYOnaJ7gLVwHu8RE\n\
gVNIFvGFZEX5rRjuO5bgSwYhZdZSZjGgkl0mQiRr2jtUVZM0xUi+HJ16MOQn13zR\n\
Z6oM2GlUoclQdkqvDhkPPBbdNjGQTDENzmhjCRrf+zS20eI6AZR2smDq3C5xgIMI\n\
59AcbJY3AgMBAAECggEAGRL0ktMRsPtHNsWk2pnVjqHjJ3+YErGZaZsUD/iofzyW\n\
ngXPxOeuZRzMa6FD75TYuOv0wnD1/xpUZjF+ys/txTsZ7PlRXiFL6PN6U1HEyOUe\n\
CLWNDZlBJzuygbiz/n6dPSOnYUfJ+riHQY5lV0UTILot/0N4IZ96suTPV59UC7Y9\n\
dN3BijrRNkTVu/c+v5rJSi6twU9LGNn10UCjtABiFG/S3fVjjkWEIrzgH79Dzsye\n\
T0rFSqrp7i467sBApsi3v1/OyVJozEjCXKf9zrqg5HkNKLub0+rLlDwC3O/BXpzA\n\
ariClwpsOwA0kbtsl8xjyxJbPoLIGJFK3YvqM6nfSQKBgQDkgEOonX3LiDip2nbO\n\
8Iw5OEderYbokAhvJonbjB1V+UdsVmgl/Vx3Qjex4sU10YS2Ooe4OatT41vRV2XZ\n\
3db/92gakhtqbNZhcAVxXPK2uSZAd3ceZNfgBDPesphRCiue8fqGSBEgGq8mPu4K\n\
oquaZCgQLRbcweMPH782j245GQKBgQC7jth1sS6Ol3otTxHSjdGmDhg09j4aD3yH\n\
bL5OH7H4uDZxw/wY/ObDWyltU4v4TRdweSkjfTvetsyv0HBGwThdVXIRTB9z07JQ\n\
hFOQs9C4uq9M8CdIbyj5YD0NHRPzt9ifgqa1V21F5sBJM+uoY4BtyZTAmDJzCbd8\n\
rY7J/i4jzwKBgQCUpqjdac+reCw8u6XtDGp80xMDEeqhIwqJnM20aVuwUaJYZYIN\n\
rNzZrNdkvz1CvNIUZtFiVQoTYeaasrvM11gGX2J3XrO9MZ7p9qFj1W8E1kB/UfjJ\n\
ahtSXgmMiC01E2O7XHp5nyqc8x8cx3W+r4LpxtyVYW/tH6libmnLydWQCQKBgQCG\n\
K3+JYcBuXMoX03Jqbu1EntyONoDiX6WzswTIGkBULmM0KwESVwg1Q+d0v8lnTK6x\n\
1Nqq+pFzls0CEFfhJaPOkKtS2GO/lfb/RkoJP7jWDSYOIdXYKTzkeAX0dZKqTB/4\n\
q5vaKbqPwKxZMX0pLlTXNNbml3mvdYn+9KEqulwDXQKBgQDcQeIEkRStrXMxOflB\n\
fxVq8mlwOxqsDV7AxvhYgQlnBDGsPpNKrUZNhyuFsAQkE8cmkMkcYvfxdGNcthLF\n\
uBenoB2G2KjmKvlujrd5ZBGcMZH9gXWt0fI34gGdZJzluLr/ZXaA8e8+Xy3u7Jm/\n\
04n+GX6otIdlxh5qmOQKzh4uNw==\n\
-----END PRIVATE KEY-----\n";
        // Embed as JSON string with escaped newlines.
        format!(
            r#"{{"project_id":"test-project","client_email":"sa@test-project.iam.gserviceaccount.com","private_key":"{}"}}"#,
            TEST_RSA_PEM.replace('\n', "\\n"),
        )
    }

    #[test]
    fn t1_4_p3b_fcm_parses_service_account_json() {
        let json = fake_service_account_json();
        let _d = FcmDispatcher::from_service_account_json(&json).unwrap();
    }

    #[test]
    fn t1_4_p3b_fcm_rejects_malformed_service_account() {
        let res = FcmDispatcher::from_service_account_json("not json");
        assert!(matches!(res, Err(PushError::InvalidToken(_))));
    }

    #[test]
    fn t1_4_p3b_fcm_jwt_signs() {
        let json = fake_service_account_json();
        let d = FcmDispatcher::from_service_account_json(&json).unwrap();
        let jwt = d.build_jwt().unwrap();
        // Three base64url-encoded segments separated by '.'.
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must be header.claims.sig");
        assert!(!parts[0].is_empty() && !parts[1].is_empty() && !parts[2].is_empty());
    }

    #[test]
    fn t489_10_fcm_wake_payload_base64_in_data_w_key() {
        // Epic 489.10 slice 4.4: a non-empty 72-byte wake payload is
        // base64-encoded into message.data under key "w"; the legacy wake=1
        // kick is preserved.
        use base64::Engine;
        let payload = [0x5Au8; 72];
        let data = build_wake_data(&payload);
        let json = serde_json::to_value(&data).unwrap();
        assert_eq!(json["wake"], "1");
        let expected_b64 = base64::engine::general_purpose::STANDARD.encode(payload);
        assert_eq!(json["w"], expected_b64);
        // base64 of 72 bytes is 96 chars (72 → ceil(72/3)*4).
        assert_eq!(expected_b64.len(), 96);
    }

    #[test]
    fn t489_10_fcm_empty_wake_payload_preserves_wake_only() {
        // Empty payload → body byte-identical to the legacy {"wake":"1"}:
        // the "w" key must be absent (serde skip_serializing_if).
        let data = build_wake_data(&[]);
        let json = serde_json::to_value(&data).unwrap();
        assert_eq!(json["wake"], "1");
        assert!(json.get("w").is_none(), "empty payload must omit the w key");
        // Confirm the serialized object has exactly one key.
        assert_eq!(json.as_object().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn t1_4_p3b_fcm_dispatch_rejects_wrong_provider() {
        let json = fake_service_account_json();
        let d = FcmDispatcher::from_service_account_json(&json).unwrap();
        let apns_token = PushToken {
            provider: PushProvider::Apns,
            token: vec![0u8; 32],
        };
        let err = d.dispatch(&apns_token, &[]).await.unwrap_err();
        assert!(matches!(
            err,
            PushError::ProviderNotConfigured(PushProvider::Apns)
        ));
    }

    #[tokio::test]
    async fn t1_4_p3b_fcm_oauth_then_send_happy_path() {
        let mock = MockServer::start().await;
        let oauth_path = "/oauth2/token";
        let send_path = "/v1/projects/test-project/messages:send";
        // 1) OAuth endpoint returns a fake bearer.
        Mock::given(method("POST"))
            .and(path(oauth_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "fake-bearer-abc",
                "expires_in": 3600,
                "token_type": "Bearer"
            })))
            .mount(&mock)
            .await;
        // 2) FCM send endpoint accepts.
        Mock::given(method("POST"))
            .and(path(send_path))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "projects/test-project/messages/abc123"
            })))
            .mount(&mock)
            .await;

        let json = fake_service_account_json();
        let d = Arc::try_unwrap(FcmDispatcher::from_service_account_json(&json).unwrap())
            .unwrap_or_else(|arc| (*arc).clone_for_test())
            .with_test_endpoints(
                Some(format!("{}{}", mock.uri(), oauth_path)),
                Some(format!("{}{}", mock.uri(), send_path)),
            );
        let token = PushToken {
            provider: PushProvider::Fcm,
            token: b"fake-fcm-registration-token".to_vec(),
        };
        d.dispatch(&token, &[]).await.unwrap();
    }

    #[tokio::test]
    async fn t1_4_p3b_fcm_404_maps_to_invalid_token() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "fake", "expires_in": 3600, "token_type": "Bearer"
            })))
            .mount(&mock)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/projects/test-project/messages:send"))
            .respond_with(ResponseTemplate::new(404).set_body_string("UNREGISTERED"))
            .mount(&mock)
            .await;

        let json = fake_service_account_json();
        let d = Arc::try_unwrap(FcmDispatcher::from_service_account_json(&json).unwrap())
            .unwrap_or_else(|arc| (*arc).clone_for_test())
            .with_test_endpoints(
                Some(format!("{}/oauth2/token", mock.uri())),
                Some(format!(
                    "{}/v1/projects/test-project/messages:send",
                    mock.uri()
                )),
            );
        let token = PushToken {
            provider: PushProvider::Fcm,
            token: b"unregistered".to_vec(),
        };
        let err = d.dispatch(&token, &[]).await.unwrap_err();
        assert!(matches!(err, PushError::InvalidToken(_)));
    }

    #[tokio::test]
    async fn cycle9_oauth_error_body_is_truncated_char_safe() {
        // audit cycle-9: a hostile/buggy provider can return a huge error body;
        // the logged PushError uses `{body:.256}` so it stays bounded and never
        // splits a UTF-8 boundary. Refuse oauth with a 4000-byte multibyte body
        // and assert the surfaced error is short + valid UTF-8.
        let mock = MockServer::start().await;
        let huge_body = "🔥".repeat(1000); // 1000 chars / 4000 bytes
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .respond_with(ResponseTemplate::new(400).set_body_string(huge_body))
            .mount(&mock)
            .await;

        let json = fake_service_account_json();
        let d = Arc::try_unwrap(FcmDispatcher::from_service_account_json(&json).unwrap())
            .unwrap_or_else(|arc| (*arc).clone_for_test())
            .with_test_endpoints(Some(format!("{}/oauth2/token", mock.uri())), None);
        let token = PushToken {
            provider: PushProvider::Fcm,
            token: b"x".to_vec(),
        };
        let err = d.dispatch(&token, &[]).await.unwrap_err();
        let msg = err.to_string();
        // Fixed prefix "oauth refused: HTTP 400 ... body=" + at most 256 body
        // chars — far under the untruncated ~4000-char blob.
        assert!(
            msg.chars().count() < 320,
            "error body must be truncated, got {} chars",
            msg.chars().count()
        );
        // Char-safe: the body fragment is whole 🔥 glyphs, never a split byte.
        assert!(msg.contains('🔥'), "truncated body must remain valid UTF-8");
    }

    #[tokio::test]
    async fn t1_4_p3b_fcm_429_maps_to_rate_limited() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "fake", "expires_in": 3600, "token_type": "Bearer"
            })))
            .mount(&mock)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/projects/test-project/messages:send"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&mock)
            .await;

        let json = fake_service_account_json();
        let d = Arc::try_unwrap(FcmDispatcher::from_service_account_json(&json).unwrap())
            .unwrap_or_else(|arc| (*arc).clone_for_test())
            .with_test_endpoints(
                Some(format!("{}/oauth2/token", mock.uri())),
                Some(format!(
                    "{}/v1/projects/test-project/messages:send",
                    mock.uri()
                )),
            );
        let token = PushToken {
            provider: PushProvider::Fcm,
            token: b"any".to_vec(),
        };
        let err = d.dispatch(&token, &[]).await.unwrap_err();
        assert!(matches!(err, PushError::RateLimited));
    }

    #[tokio::test]
    async fn t1_4_p3b_fcm_oauth_500_maps_to_transport() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock)
            .await;

        let json = fake_service_account_json();
        let d = Arc::try_unwrap(FcmDispatcher::from_service_account_json(&json).unwrap())
            .unwrap_or_else(|arc| (*arc).clone_for_test())
            .with_test_endpoints(Some(format!("{}/oauth2/token", mock.uri())), None);
        let token = PushToken {
            provider: PushProvider::Fcm,
            token: b"any".to_vec(),
        };
        let err = d.dispatch(&token, &[]).await.unwrap_err();
        assert!(matches!(err, PushError::Transport(_)));
    }

    // Test-only helper: clone the inner parts when an Arc<FcmDispatcher>
    // would otherwise prevent direct mutation via with_test_endpoints.
    #[cfg(test)]
    impl FcmDispatcher {
        fn clone_for_test(&self) -> Self {
            Self {
                service_account: self.service_account.clone(),
                http: self.http.clone(),
                send_url: self.send_url.clone(),
                token_cache: Mutex::new(None),
                oauth_url_override: self.oauth_url_override.clone(),
                send_url_override: self.send_url_override.clone(),
            }
        }
    }
}
