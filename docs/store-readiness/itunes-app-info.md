# iTunes Connect / App Store Connect — Encryption questions

Apple asks every app submission whether it uses encryption. A wrong
answer can stall a review for a week. Use these answers verbatim.

## App Information → Encryption

**Q: Does your app use encryption?**
> Yes

**Q: Does your app meet any of the following criteria? (mass-market
encryption exemption)**
> ✅ Your app uses, accesses, contains, implements or incorporates
> encryption that is exempt under Section 740.17(b)(1) of the U.S.
> Export Administration Regulations [...].

(All of veil's cryptographic primitives qualify under the Note 3
mass-market provisions.)

**Q: Is your app exempt from upload of compliance documentation under
ENC?**
> ✅ Your app is exempt because:
> * it has been authorized to ship under §740.17(b)(1) (with a filed
>   ERN);
> * cryptographic functions are NOT user-restricted (ANY user
>   downloading the app gets the same crypto);
> * the symmetric key length is ≤ 256 bits.

**Required upload:** the annual encryption-status letter referencing
the ERN. Template:

```
[Date]

To: Bureau of Industry and Security
    U.S. Department of Commerce

Subject: Annual self-classification report — ERN <YOUR-ERN>

This letter confirms that the cryptographic functionality в veil
([app name], v[version]) remains classified as ECCN 5D002.c.1 mass-
market (License Exception ENC §740.17(b)(1)).  Cryptographic
primitives используемые в this release:

  - ChaCha20-Poly1305 (256-bit symmetric AEAD)
  - Ed25519 + X25519 (Curve25519 family signatures + ECDH)
  - Falcon-512 (post-quantum signatures, ≤ 256-bit effective security)
  - ML-KEM-768 (post-quantum KEM, ≤ 256-bit effective security)
  - BLAKE3, SHA-256, SHA-3 (hash families)

No changes к the above primitive set since the prior reporting period.

Sincerely,
[Operator Name + Title]
[Email]
```

## Build Settings

In Xcode → Build Settings, set `ITSAppUsesNonExemptEncryption = NO`
in the Info.plist:

```xml
<key>ITSAppUsesNonExemptEncryption</key>
<false/>
```

This skips Apple's per-build prompt asking the same question, and it
locks the answer at build time, so a consumer-app developer can't
accidentally set it to YES (which would trigger a review pause).

## Per-jurisdiction availability

Set in App Store Connect → Pricing and Availability:

* **Available territories:** All except those subject to OFAC
  sanctions (Cuba, Iran, North Korea, Syria, Crimea, etc.).
* Apple maintains the up-to-date sanctioned list — use the platform
  default ("All"), which Apple filters automatically.

## TestFlight notes

TestFlight builds are subject to the same export-control rules. Use
the SAME ERN; no separate filing. Add the operator's tester roster
to "Internal Testers" before you submit. Otherwise a reviewer can't
register, pair, or verify push — veil needs a second party to pair
with before any messaging works.
