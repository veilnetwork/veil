# Google Play Console — Data Safety form

Submit at: https://play.google.com/console → All apps → (your app)
→ App content → Data safety.  Google displays these as the "Data
safety" section on the Play Store listing.

## Section 1 — Data collection and security

### Does your app collect or share any of the required user data types?

**Answer:** Yes. (Required for messaging apps that exchange user
content through the network, even when that content is end-to-end
encrypted. For the form, Google counts transit through any
third-party infrastructure — relays included — as "sharing".)

### Is all of the user data collected by your app encrypted in transit?

**Answer:** Yes. All veil frames between nodes are protected by:
* TLS 1.3 transport (port 443) with operator-supplied certs, OR
* QUIC + the OVL1 handshake + post-quantum hybrid key exchange
  (ML-KEM-768 + X25519) for inter-veil sessions.

### Do you provide a way for users to request that their data be deleted?

**Answer:** Yes. Users can:
* Delete the app, or the in-app "forget all" action, which performs
  a local wipe of the on-device identity, private keys, and message
  history.
* Deletion is entirely local: veil publishes no network-side
  revocation. There is no in-band revocation flow. Any short-lived
  delegated subkeys the identity issued simply age out on their own
  once their `valid_until_unix` validity window elapses.

## Section 2 — Data types

For each data type, declare whether it is collected (sent off the
device to a server controlled by the developer) AND/OR shared (sent
to a third party).

### Personal info

| Type | Collected | Shared | Optional | Purpose | Reason |
|------|-----------|--------|----------|---------|--------|
| Name | No | No | — | — | App does not transmit user names anywhere |
| Email address | No | No | — | — | Identity is a cryptographic key, not tied to email |
| User IDs | No | No | — | — | Sovereign identity stays on-device |
| Address | No | No | — | — | — |
| Phone number | No | No | — | — | — |
| Race and ethnicity | No | No | — | — | — |
| Political orientation | No | No | — | — | — |
| Sexual orientation | No | No | — | — | — |
| Other info | No | No | — | — | — |

### Financial info

All categories: **No** — veil carries no financial data.

### Health and fitness

All categories: **No**.

### Messages

| Type | Collected | Shared | Optional | Purpose | Reason |
|------|-----------|--------|----------|---------|--------|
| Emails | No | No | — | — | — |
| SMS or MMS | No | No | — | — | — |
| Other in-app messages | No | **Yes** (transit only) | Yes | App functionality | Messages are E2E-encrypted and pass through veil relays, which CANNOT decrypt them. Disclosed as "shared" because frames transit non-developer infrastructure (peer relays) — Google's spec treats this as sharing even when zero plaintext is exposed. |

### Photos and videos, Audio files, Files and docs

Default: **No**, unless the consumer app adds attachment support.

### Calendar, Contacts

All categories: **No**.

### App activity, App info and performance, Device or other IDs

All categories: **No** — veil logs no analytics and sends no crash
reports. Device IDs (IDFA, ANDROID_ID, GAID) are not read.

### Web browsing, Audio
All categories: **No**.

## Section 3 — Security practices

### Data encryption in transit

**Yes**, all data in transit is encrypted.  Mechanism:
* TLS 1.3 (rustls), or
* QUIC + the OVL1 handshake + ML-KEM-768 hybrid post-quantum key exchange.

### Encryption details (free-text)

> Veil uses a post-quantum hybrid handshake that combines Ed25519 +
> Falcon-512 identity signatures with ML-KEM-768 for session-key
> establishment. AEAD: ChaCha20-Poly1305. Frames are wrapped in a
> padding scheme so passive network observers cannot infer message
> lengths. An optional anonymity layer (Tor-like circuits through 3
> relays) is available as a per-recipient opt-in.

### Independent security review

* Internal: **Yes**, ongoing. The Phase 6.45, 6.47, and 6.48
  multi-agent security audits are closed (see TASKS_ARCHIVE.md).
* External: **Pending** — a third-party audit is planned before the
  1.0 release. Update this section after the audit.

## Section 4 — Account deletion

**Required answer for messaging apps:** Yes, our app provides
in-app account deletion. Document the path: Settings → Identity →
Delete identity. This is a local wipe of the on-device identity,
private keys, and message history; no revocation is published to the
network (there is no in-band revocation flow), and any short-lived
delegated subkeys expire on their own once their validity window
elapses. Restoration is impossible without the 24-word BIP-39 phrase
the user explicitly chose to back up.

**Web URL for off-device deletion:** N/A — there is no server-side
state to delete.
