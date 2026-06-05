# Export-control compliance (US BIS)

Veil ships strong cryptography (Ed25519, Falcon-512, ML-KEM-768,
ChaCha20-Poly1305).  US Bureau of Industry and Security (BIS)
classifies all such products under Export Control Classification
Number **5D002.c.1**.  The "mass-market" exception (License
Exception ENC §740.17(b)(1)) covers ordinary consumer apps, but
shipping companies still must:

1. Self-classify before first export (BIS reviews "ENC reports"
   к catch misclassified items).
2. File an annual "self-classification report" (called а **CCATS**
   semi-annually OR an **ERN** under §740.17(b)).
3. Re-file whenever the encryption algorithms change materially.

## Step 1 — One-time self-classification

Determine ECCN.  For veil:
* **ECCN:** 5D002.c.1 — "encryption commodities, software, и
  technology classified в Note 3 — mass-market".
* **ECCN paragraph reason:** Note 3 applies because:
  * the app is sold OR distributed without restriction;
  * the cryptographic functionality is not user-modifiable;
  * the symmetric key length is ≤ 256 bits (veil uses 256-bit
    ChaCha20).

## Step 2 — File ERN through SNAP-R

Submit at: https://www.bis.doc.gov/index.php/snap-r

Required fields (template):

```
Authorization Type:                ENC
Encryption Authorization Type:     Mass-market (Section 740.17(b)(1))
Encryption Item Type:              §740.17(b)(1) item — software application
Description of the encryption item: 
  Decentralized peer-to-peer messaging mobile / desktop application.
  End-to-end encrypted между users using ML-KEM-768 hybrid post-
  quantum key encapsulation, Ed25519 + Falcon-512 identity
  signatures, ChaCha20-Poly1305 AEAD bulk cipher.  Distributed
  through Apple App Store, Google Play Store, и direct download
  from project site.

Symmetric algorithms used и max key sizes:
  - ChaCha20  (256-bit key)

Asymmetric algorithms:
  - Ed25519 (signatures)
  - X25519  (key agreement)
  - Falcon-512 (post-quantum signatures)
  - ML-KEM-768 (post-quantum KEM, ≤ 256 bits effective)

Hash algorithms:
  - BLAKE3
  - SHA-256
  - SHA-3

Source code public availability:    Yes (open-source under MIT)
Source code repository:             https://github.com/<org>/veil

Contact for technical questions:    <operator email>
```

After submitting SNAP-R returns an **ERN (Encryption Registration
Number)**.  Save it.  Apple App Store and Google Play Store both
ask for this number в the export-compliance section of submission
forms.

## Step 3 — Annual report

Each calendar year by **February 1**, file а short status report
even if nothing changed:

```
ERN: <your ERN>
Reporting period: <prior calendar year>
Changes since last report: <list>
Cryptographic primitives unchanged: yes / no
```

Submit through the same SNAP-R portal under the existing ERN.

## Re-classification triggers

File а new ERN OR updated CCATS submission when ANY of:
* New asymmetric primitive added (e.g. switching из Falcon к
  Dilithium would require re-filing).
* Symmetric key length changes >256 bits.
* New language / runtime that drags в additional cryptographic
  libraries (e.g. adding embedded Tor would trigger).
* Revenue model changes к non-mass-market (e.g. selling enterprise
  licenses adds different filing obligations).

## Apple App Store / Google Play Store submission fields

### App Store Connect (Apple)

1. **App Information → Encryption:** Yes, contains encryption.
2. **Export Compliance Documentation Required:** Yes.
   * Upload а short letter referencing the ERN, attesting к §740.17(b)(1)
     mass-market exception eligibility.
3. **Annual self-classification report:** "Yes, we maintain an annual
   ERN status report с BIS."

### Google Play Console

1. **App content → US export laws:** declare "compliant с US export
   laws"; note that mass-market apps don't need а separate license.

## Other jurisdictions

* **EU:** Dual-Use Regulation 2021/821 — mass-market exception
  ("publicly available" criterion) applies; no separate filing for
  open-source projects.
* **France:** AR-26 declaration; usually waived for open-source
  encryption ≤ 256-bit symmetric.
* **Russia / China / other restrictive markets:** consult local
  counsel; typically these markets are EXIT-controlled (operator
  may need к exclude these countries из the storefront).
