# Privacy Policy — veil messaging app

> Drop-in template for consumer apps. Replace the `[App Name]` and
> `[Operator Email]` placeholders before publishing.

---

## Privacy Policy

**Effective Date:** [Year]-[Month]-[Day]
**App:** [App Name]
**Operator:** [Operator Name / Org]

[App Name] is a privacy-first peer-to-peer messaging application.
We have no servers. We do not collect personal data. This document
describes the few data interactions that DO happen, and how they
protect your privacy.

### 1. Information we do not collect

* We do not collect, store, or process any of your personal data on
  any server we control — because we operate no servers.
* We do not use third-party analytics, tracking, advertising, or
  crash-reporting SDKs.
* We do not read your contacts, photos, calendar, location, or other
  device data unless you explicitly opt in to a feature that needs
  them (none ship by default).
* We do not assign you a user ID, account number, or IDFA-style
  identifier.

### 2. Information that stays on your device

The following data lives only on your device, encrypted at rest under
a passphrase you choose (Argon2id key derivation, 128-bit minimum
recommended):

* Your sovereign identity key (a cryptographic key pair you generated
  on first launch).
* Your contact list (other users' identity public keys, with optional
  display names you assign).
* Your message history.
* Application preferences.

If you uninstall the app, this data is removed under standard OS rules.

### 3. Information that transits the veil network

Messages you send are end-to-end encrypted ON YOUR DEVICE before
they leave it. Encrypted frames travel through veil relays operated
by other users. Relays cannot decrypt the content, and they discard
frames after delivery.

The encryption uses a post-quantum hybrid scheme:
* Identity signatures: Ed25519 + Falcon-512 (forward-secure even
  if quantum computers break Ed25519).
* Session-key establishment: ML-KEM-768 + X25519 (forward-secure
  even if quantum computers break X25519).
* Bulk encryption: ChaCha20-Poly1305 AEAD (256-bit symmetric key).

### 4. Push notifications (optional)

If you enable push notifications:
* The push token (provided by Apple APNs OR Google FCM) is stored
  on your device.
* The token is sent to relays in a sealed form readable only by a
  push relay node operator (think of a mailbox carrier — they know
  "user X received a wake-up" but cannot see the message).
* The push payload always contains JUST the wake-up signal — never
  message content.

You can disable push notifications in the app settings without losing
messaging functionality. Messages still arrive; there's just no
immediate wake-up unless the app is in the foreground.

### 5. Third-party services

The app uses standard mobile OS services:
* Apple iOS: keychain (for token storage), background tasks, push
  notifications (when enabled).
* Google Android: shared preferences, foreground service, push
  notifications (when enabled).
* No other third-party services.

If push notifications are enabled, Apple APNs OR Google FCM see
"app installation X received a silent push at time T" — that's the
minimum metadata Apple/Google receive. It's no more than ANY
push-enabled app exposes.

### 6. Children's privacy

The app is not directed at children under 13. If you are a parent
and believe your child has used the app, please contact us at
[Operator Email]. We'll provide instructions for wiping the
on-device identity and uninstalling.

### 7. Data retention

* On your device: until you delete the app OR explicitly clear data.
* In transit: relays drop frames after delivery (typical retention
  of cached encrypted blobs: 24 h max, configurable per-deployment).
* On servers: not applicable (no servers).

### 8. Your rights

Because we do not collect data on servers, the traditional rights
(access, deletion, portability) have no server-side endpoint to
exercise. The equivalent on-device controls:

* **Access:** all your data is on your device — open the app's
  data folder.
* **Deletion:** uninstall the app, OR in-app: Settings → Delete
  identity (publishes a cryptographic revocation to the network so
  old keys cannot be impersonated).
* **Portability:** Settings → Export 24-word phrase (this phrase
  restores your identity on any device running veil).

### 9. Changes to this policy

We will notify users of material changes through the app's release
notes and by updating the "Effective Date" above.

### 10. Contact

[Operator Email] for privacy questions. Public bug tracker:
[Issue tracker URL].
