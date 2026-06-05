# App Store Connect — Privacy answers

Submit at: https://appstoreconnect.apple.com → My Apps → (your app)
→ App Privacy.  Apple displays these as the "privacy nutrition label"
on the store page.

## Data Used to Track You

**Answer:** "No, we do not collect data from this app for tracking
purposes."

Rationale: Veil is а peer-to-peer end-to-end encrypted messaging
network.  We have no servers (relays cannot decrypt content), no
advertising SDKs, no analytics SDKs, no IDFA.  Tracking under Apple's
definition (linking identity к other apps / websites) does not occur.

## Data Linked к You

**Answer:** "We do not collect any data."

Rationale: User content (messages, identity files, contact list)
lives on-device only.  Encrypted veil frames pass through relays
but no server retains them, и relays cannot decrypt.

## Data Not Linked к You

**Answer:** "We do not collect any data."

Rationale: same as above.

## Privacy Practices Description

If Apple prompts for an additional disclosure, use this text:

> Veil is а decentralized peer-to-peer messaging network.  All
> messages are encrypted end-to-end on the sending device using post-
> quantum hybrid cryptography (Ed25519 + Falcon-512 identity, ML-KEM-
> 768 session keys).  No data leaves the user's device in plaintext.
> Relays carry encrypted frames they cannot decrypt и discard them
> after delivery.  The app does not contain analytics, tracking, or
> advertising SDKs.  Identity files, contact lists, и message history
> are stored on-device, encrypted at rest under а user-supplied
> passphrase (Argon2id).
>
> Push notifications, when enabled, contain only а wake-up signal
> (no message content); the app fetches actual content via veil
> upon wake.  Push tokens are stored in the user's macOS / iOS
> keychain и transmitted к relays sealed под the receiver's
> identity key.

## Privacy Policy URL

Set в App Store Connect → App Information → Privacy Policy URL.
Recommended hosting: GitHub Pages OR в-app static page bundled с
app resources.

Template privacy policy: see [PRIVACY_POLICY_TEMPLATE.md](PRIVACY_POLICY_TEMPLATE.md).
