# Store-readiness checklist (Epic 489.9)

What the consumer-app operator must hand over to ship veil through
the Apple App Store and Google Play Store. It also covers the
export-control filings that every app shipping encryption has to
keep current.

The plugin (`flutter/veil_flutter`) ships its own privacy manifest
([`ios/Resources/PrivacyInfo.xcprivacy`](../../flutter/veil_flutter/ios/Resources/PrivacyInfo.xcprivacy)),
and consumer apps inherit it. The documents in this directory cover
material that does NOT live in the plugin. It's per-app metadata the
operator submits to the stores.

## Files

| File | Purpose | Where it goes |
|------|---------|--------------|
| [`app-store-privacy.md`](app-store-privacy.md) | App Store Privacy "nutrition label" answers | App Store Connect → App Privacy section |
| [`play-store-data-safety.md`](play-store-data-safety.md) | Google Play Data Safety form answers | Play Console → App content → Data safety |
| [`export-control.md`](export-control.md) | BIS encryption self-classification + annual ERN | https://www.bis.doc.gov/index.php/snap-r |
| [`itunes-app-info.md`](itunes-app-info.md) | iTunes Connect "Encryption" question + ECCN | App Store Connect → App Information |

## Checklist before submission

* [ ] Store privacy answers match the truth ("we encrypt; we don't
      track; we don't run analytics").
* [ ] Export Compliance: ERN filed with BIS; ECCN 5D002.c.1 (mass-market)
      claimed.
* [ ] Privacy manifest present and signed (Xcode handles signing).
* [ ] No third-party SDKs added that contradict the manifest.
* [ ] App Store / Play Store screenshots show realistic chat traffic
      (no "demo dummy data" — reviewers flag it).
* [ ] Screenshot localization covers RU + EN minimum (target market).
* [ ] Tester accounts (TestFlight / Play Internal) provisioned BEFORE
      first submit so reviewers can register / pair.

## Annual maintenance

* **Export attestation** — re-file the BIS ERN by Feb 1 each calendar
  year (there's a penalty for missing it).
* **Privacy manifest** — re-audit when you add a new third-party
  SDK. Apple's required-reason API list changes occasionally.
* **Data safety form** — Google requires you to re-affirm whenever you
  release a new app version that touches data handling.
