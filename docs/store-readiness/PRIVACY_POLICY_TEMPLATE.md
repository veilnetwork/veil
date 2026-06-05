# Privacy Policy — veil messaging app

> Drop-in template для consumer apps.  Replace `[App Name]` и
> `[Operator Email]` placeholders before publishing.

---

## Privacy Policy

**Effective Date:** [Year]-[Month]-[Day]
**App:** [App Name]
**Operator:** [Operator Name / Org]

[App Name] is а privacy-first peer-to-peer messaging application.
We do not have servers.  We do not collect personal data.  This
document describes the few data interactions that DO happen и how
they protect your privacy.

### 1. Information we do not collect

* We do not collect, store, or process any of your personal data on
  any server we control — because we operate no servers.
* We do not use third-party analytics, tracking, advertising, or
  crash-reporting SDKs.
* We do not read your contacts, photos, calendar, location, or other
  device data unless you explicitly opt in to а feature that needs
  them (none ship by default).
* We do not assign you а user ID, account number, or IDFA-style
  identifier.

### 2. Information that stays on your device

The following data lives only on your device, encrypted at rest under
а passphrase you choose (Argon2id key derivation, 128-bit minimum
recommended):

* Your sovereign identity key (а cryptographic key pair you generated
  on first launch).
* Your contact list (other users' identity public keys, with optional
  display names you assign).
* Your message history.
* Application preferences.

If you uninstall the app, this data is removed по standard OS rules.

### 3. Information that transits через the veil network

Messages you send are end-to-end encrypted ON YOUR DEVICE before
leaving it.  Encrypted frames travel through veil relays operated
by other users; relays cannot decrypt the content и discard frames
после delivery.

The encryption uses а post-quantum hybrid scheme:
* Identity signatures: Ed25519 + Falcon-512 (forward-secure even
  если quantum computers break Ed25519).
* Session-key establishment: ML-KEM-768 + X25519 (forward-secure
  even если quantum computers break X25519).
* Bulk encryption: ChaCha20-Poly1305 AEAD (256-bit symmetric key).

### 4. Push notifications (optional)

If you enable push notifications:
* The push token (provided by Apple APNs OR Google FCM) is stored
  on your device.
* The token is sent к relays in а sealed form readable only by а
  push relay node operator (think mailbox carrier — they know "user
  X received а wake-up" but cannot see the message).
* Push payload always contains JUST the wake-up signal — never
  message content.

You can disable push notifications в the app settings without losing
messaging functionality (messages still arrive; just no immediate
wake-up unless the app is foregrounded).

### 5. Third-party services

The app uses standard mobile OS services:
* Apple iOS: keychain (for token storage), background tasks, push
  notifications (когда enabled).
* Google Android: shared preferences, foreground service, push
  notifications (когда enabled).
* No other third-party services.

If push notifications are enabled, Apple APNs OR Google FCM see
"app installation X received а silent push at time T" — that's the
minimum metadata Apple/Google receive.  This is no more than ANY
push-enabled app.

### 6. Children's privacy

The app is not directed at children under 13.  If you are а parent
и believe your child has used the app, please contact us at
[Operator Email] и we'll provide instructions для wiping the
on-device identity и uninstalling.

### 7. Data retention

* On your device: until you delete the app OR explicitly clear data.
* In transit: relays drop frames после delivery (typical retention
  of cached encrypted blobs: 24 h max, configurable per-deployment).
* On servers: not applicable (no servers).

### 8. Your rights

Because we do not collect data on servers, traditional rights
(access, deletion, portability) do not have а server-side endpoint
к exercise.  Equivalent on-device controls:

* **Access:** all your data is on your device — open the app's
  data folder.
* **Deletion:** uninstall the app, OR в-app: Settings → Delete
  identity (publishes а cryptographic revocation к the network so
  old keys cannot be impersonated).
* **Portability:** Settings → Export 24-word phrase (this phrase
  restores your identity on any device running veil).

### 9. Changes к this policy

We will notify users of material changes via the app's release
notes и by updating the "Effective Date" above.

### 10. Contact

[Operator Email] для privacy questions.  Public bug tracker:
[Issue tracker URL].
