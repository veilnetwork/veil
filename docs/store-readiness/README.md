# Store-readiness checklist (Epic 489.9)

Material the consumer-app operator must furnish to ship veil
through the Apple App Store + Google Play Store, plus the
export-control filings every encryption-shipping app needs to keep
current.

The plugin (`flutter/veil_flutter`) ships its own privacy manifest
([`ios/Resources/PrivacyInfo.xcprivacy`](../../flutter/veil_flutter/ios/Resources/PrivacyInfo.xcprivacy));
consumer apps inherit it.  The documents в this directory describe
material that DOES NOT live в the plugin — it's per-app metadata
the operator submits к the stores.

## Files

| File | Purpose | Where it goes |
|------|---------|--------------|
| [`app-store-privacy.md`](app-store-privacy.md) | App Store Privacy "nutrition label" answers | App Store Connect → App Privacy section |
| [`play-store-data-safety.md`](play-store-data-safety.md) | Google Play Data Safety form answers | Play Console → App content → Data safety |
| [`export-control.md`](export-control.md) | BIS encryption self-classification + annual ERN | https://www.bis.doc.gov/index.php/snap-r |
| [`itunes-app-info.md`](itunes-app-info.md) | iTunes Connect "Encryption" question + ECCN | App Store Connect → App Information |

## Checklist before submission

* [ ] Store privacy answers match the truth ("we encrypt; we don't
      track; we don't analytics").
* [ ] Export Compliance: ERN filed с BIS; ECCN 5D002.c.1 (mass-market)
      claimed.
* [ ] Privacy manifest present + signed (Xcode handles signing).
* [ ] No third-party SDKs added that contradict the manifest.
* [ ] App Store / Play Store screenshots show realistic chat traffic
      (no "demo dummy data" — reviewers flag это).
* [ ] Screenshot localization covers RU + EN minimum (target market).
* [ ] Tester accounts (TestFlight / Play Internal) provisioned BEFORE
      first submit so reviewers can register / pair.

## Annual maintenance

* **Export attestation** — re-file BIS ERN by Feb 1 each calendar
  year (penalty for missing).
* **Privacy manifest** — re-audit when adding а new third-party
  SDK; Apple's required-reason API list changes occasionally.
* **Data safety form** — Google requires re-affirming whenever you
  release а new app version that touches data handling.
