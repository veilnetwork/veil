# Google Play Console — Data Safety form

Submit at: https://play.google.com/console → All apps → (your app)
→ App content → Data safety.  Google displays these as the "Data
safety" section on the Play Store listing.

## Section 1 — Data collection и security

### Does your app collect or share any of the required user data types?

**Answer:** Yes.  (Required for messaging apps that exchange user
content through the network, even when content is end-to-end
encrypted.  Google considers transit through any third-party
infrastructure — including relays — as "sharing" for the form.)

### Is all of the user data collected by your app encrypted in transit?

**Answer:** Yes.  All veil frames между nodes are protected by:
* TLS 1.3 transport (port 443) with operator-supplied certs OR
* QUIC + Noise IK + post-quantum hybrid key exchange (ML-KEM-768
  + X25519) для inter-veil sessions.

### Do you provide а way for users к request that their data be deleted?

**Answer:** Yes.  Users can:
* Delete the app, which wipes the on-device identity + message
  history.
* Use `veil-cli identity delete` (or in-app equivalent) к
  cryptographically retire their sovereign identity (publishes а
  RevocationCert к the DHT so old keys cannot be impersonated).

## Section 2 — Data types

For each data type, declare whether it is collected (sent off the
device к а server controlled by the developer) AND/OR shared (sent
к а third party).

### Personal info

| Type | Collected | Shared | Optional | Purpose | Reason |
|------|-----------|--------|----------|---------|--------|
| Name | No | No | — | — | App does not transmit user names anywhere |
| Email address | No | No | — | — | Identity is а cryptographic key, not email-tied |
| User IDs | No | No | — | — | Sovereign identity stays on-device |
| Address | No | No | — | — | — |
| Phone number | No | No | — | — | — |
| Race и ethnicity | No | No | — | — | — |
| Political orientation | No | No | — | — | — |
| Sexual orientation | No | No | — | — | — |
| Other info | No | No | — | — | — |

### Financial info

All categories: **No** — veil carries no financial data.

### Health и fitness

All categories: **No**.

### Messages

| Type | Collected | Shared | Optional | Purpose | Reason |
|------|-----------|--------|----------|---------|--------|
| Emails | No | No | — | — | — |
| SMS or MMS | No | No | — | — | — |
| Other in-app messages | No | **Yes** (transit only) | Yes | App functionality | Messages are E2E-encrypted и pass through veil relays which CANNOT decrypt them.  Disclose as "shared" because frames transit non-developer infrastructure (peer relays) — Google's spec treats this as sharing even when zero plaintext is exposed. |

### Photos и videos, Audio files, Files и docs

Default: **No** unless the consumer app adds attachment support.

### Calendar, Contacts

All categories: **No**.

### App activity, App info и performance, Device or other IDs

All categories: **No** — veil does not log analytics nor send
crash reports.  Device IDs (IDFA, ANDROID_ID, GAID) are not read.

### Web browsing, Audio
All categories: **No**.

## Section 3 — Security practices

### Data encryption in transit

**Yes**, all data in transit is encrypted.  Mechanism:
* TLS 1.3 (rustls), or
* QUIC + Noise IK + ML-KEM-768 hybrid post-quantum key exchange.

### Encryption details (free-text)

> Veil uses а post-quantum hybrid handshake combining Ed25519 +
> Falcon-512 identity signatures с ML-KEM-768 для session-key
> establishment.  AEAD: ChaCha20-Poly1305.  Frames are wrapped в
> а padding scheme so passive network observers cannot infer
> message lengths.  Optional anonymity layer (Tor-like circuits
> через 3 relays) available as per-recipient opt-in.

### Independent security review

* Internal: **Yes**, ongoing.  Phase 6.45 + Phase 6.47 + Phase 6.48
  multi-agent security audits closed (см. TASKS_ARCHIVE.md).
* External: **Pending** — third-party audit planned before 1.0
  release.  Update this section after audit.

## Section 4 — Account deletion

**Required answer for messaging apps:** Yes, our app provides
in-app account deletion. Document the path: Settings → Identity →
Delete identity (publishes а RevocationCert к the DHT, retires the
sovereign key cryptographically; restoration impossible without the
24-word BIP-39 phrase которую user explicitly chose к back up).

**Web URL для off-device deletion:** N/A — no server-side state к
delete.
