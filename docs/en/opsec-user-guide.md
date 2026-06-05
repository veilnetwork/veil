# OpSec user guide

Physical-security and social-engineering guidance for veil
identity holders.  These are things veil **cannot** protect
you from at the protocol layer — you have to do them yourself.

For protocol defences, see [`identity-model.md`](identity-model.md).
For recovery from compromise, see [`recovery.md`](recovery.md).

---

## 1. The threat model veil *does* defend against

- Passive wire-taps observing veil traffic.
- Malicious DHT nodes serving forged records.
- Compromised peers relaying stale revocations.
- Attackers with one device's `identity_sk` trying to impersonate
  the whole identity.
- An offline owner vs. attackers trying to replay pre-revocation
  records.
- Name squatters trying to register `@alice` for themselves.
- Eclipse attacks on `@name` resolution.

The cryptographic primitives — BLAKE3 preimages, Ed25519 /
Falcon-512 signatures, ChaCha20-Poly1305 AEAD, ML-KEM-768
encapsulation, HKDF-SHA256 derivation, rarity-PoW — cover all of
the above, assuming their security holds.

---

## 2. The threat model veil does **NOT** defend against

No protocol can defeat these; you have to own the defence:

1. **Shoulder-surfing during BIP-39 display.**  Anyone standing
   behind you when you run `identity create` can photograph the
   24 words with their phone and reconstruct your entire
   identity.
2. **Phishing "veil support asking for your phrase."**  There
   is no such support.  Nobody needs your BIP-39 phrase to help
   you.  If an email, chat message, or "tech support" call asks
   for it, the sender is stealing your identity.
3. **Screenshots / camera rolls / clipboards of your BIP-39
   phrase.**  Any device that touches the phrase in plaintext
   can leak it.
4. **Keyloggers on the machine you use to type the phrase.**
   The phrase is typed when restoring; a keylogger captures it.
5. **Coercion — somebody with a wrench asking for your phrase.**
   Veil has no duress-mode disclosure at present.
6. **Physical theft of an unlocked device.**  The `identity_sk`
   is held hot on the device.  If the device is unlocked when
   stolen, the attacker has the key until you revoke.
7. **Supply-chain attacks on the veil binary itself.**  If
   the binary you run is backdoored, no protocol layer protects
   you.  Verify signatures on release artefacts.

---

## 3. Physical-security checklist

### 3.1. During `identity create`

☐ Run on an **offline machine** if you take OpSec seriously.  A
laptop with WiFi disabled is a reasonable first tier; an
air-gapped machine that has never been online is the paranoia
tier.

☐ **Dim the screen.**  BIP-39 display leaks via reflections and
shoulder-surfing.  Turn the brightness down, face a wall.

☐ **No cameras in view.**  Take a look around before the CLI
shows the phrase.  Phones on tables with the camera visible,
laptop webcams, ceiling-mounted security cams — all read the
screen if they have line of sight.

☐ **Write the phrase by hand on paper** before typing the
confirmation words back.  The CLI will ask you to retype 3
random words; that's the point — it's confirming you've
written it down somewhere the CLI does not know about.

☐ **Store the paper safely before the CLI session ends.**
Fireproof safe, safe deposit box, or a sealed envelope in a
location only you know.  The paper is more important than the
laptop.

☐ **Do not photograph, scan, or otherwise digitise the paper**
except through the purpose-built encrypted QR backup flow,
which requires a password never stored on the same machine.

### 3.2. Daily use

☐ Lock the screen whenever you step away.  `identity_sk` is
held hot by the running veil process.  Screen-lock is the
last line of defence.

☐ Disable auto-mount of USB storage.  A keylogger dropped from
a plugged-in drive can intercept your next BIP-39 entry during
a restore.

☐ Use full-disk encryption on every device.  Prevents an
attacker with physical access from extracting
`~/.config/veil/identity.toml` offline.

☐ Treat the encrypted `master.enc` as only weakly confidential.
Argon2id + ChaCha20-Poly1305 buys time — not forever — against
a determined attacker with the file and unlimited GPUs.  Use a
strong password (diceware, ≥ 6 words).

### 3.3. Pairing a new device

☐ Pair **in person** when possible.  Hold both screens side by
side; compare the 6-digit OOB code directly.

☐ If remote pairing is unavoidable, compare the OOB code over a
**pre-established trusted channel** (phone call to a number you
memorised before needing it; a signed video-call with both
faces visible).  Do **NOT** compare via the same channel
you're about to start using — an attacker controlling the
channel could mediate both ends.

☐ **Abort if codes don't match.**  Mismatch means somebody is
man-in-the-middling you.  The paired device becomes an attacker's
device.  Aborting is always safe; reconfirming is not.

### 3.4. Recovery

☐ Restore on a **clean device.**  Don't restore into the
suspected-compromised machine you just had stolen back.  Buy
fresh hardware, install veil from verified release
artefacts, restore there.

☐ After a compromise, run
`veil-cli identity status` and read every anomaly the
watcher reports.  An attacker may have added an unauthorised
device you need to revoke.

☐ Rotate your safety numbers with contacts you care about.  A
post-compromise identity has the same `identity_id` but new
`identity_keys`, so the safety number changes.  Contacts will
see an alert; have a call with them to re-confirm.

---

## 4. The phishing catalogue

Real-world attack patterns we expect to see:

### 4.1. "Veil support"

Email / DM / forum post: *"Hi, we noticed suspicious activity
on your @alice identity.  Please send us your BIP-39 phrase so
we can secure it."*

**Never do this.**  No support organisation that exists now,
ever existed, or ever will exist has any reason to see your
phrase.  The phrase literally is your identity.  Handing it
over hands the identity over.

### 4.2. Fake restore flow

A fake binary or website asks you to "paste your phrase here to
verify you still control the identity."

**Never do this either.**  The only legitimate BIP-39 entry is
into the official `veil-cli identity restore` command
running on a machine you trust.  Nothing else.

### 4.3. QR-scan hijack on pairing

During pairing, an attacker's app intercepts the QR scan and
presents a forged OOB code.  Defence: the genuine OOB code is
displayed on the source device (the one with master_seed), and
the target device shows the same code *computed from the real
pairing session key*.  If an attacker-in-the-middle is
mediating, their fake target cannot display the source's code.

Mitigation in practice: **always compare codes visually** before
tapping "confirm" on the source.  The security of the pairing
depends on this step.

### 4.4. Name-registration spoofing

An attacker registers `@a1ice` (with a digit one) hoping you
don't notice.  Or tries a look-alike where the "a" is replaced by
the Cyrillic letter "a" (Unicode U+0430), which is visually
identical to the Latin "a".

Protocol defence: veil's name whitelist is ASCII-only and
forbids Unicode characters entirely, so the Cyrillic look-alike is
rejected at decode time.  `@a1ice` is technically a valid distinct
name, so
**check the handle spelling before adding a contact**.  The safety
number is the ultimate arbiter — two names with visually similar
spellings have completely different 60-digit fingerprints.

### 4.5. "Please confirm this transaction by reading your
    safety number"

Real safety-number verification is **you reading** the 60 digits
to your contact over a trusted channel — not them reading them
to you.  Reversing the direction lets an attacker feed you their
forged number and have you confirm it.

---

## 5. Backup hygiene

- **Multiple geographically-separated paper copies.**  One in your
  home safe, one in a family member's or lawyer's hands.  A house
  fire takes out one copy; a legal seizure takes out another; a
  3-place distribution is robust against any single event.
- **Rotate the encrypted file annually.**  Delete the old
  `master.enc`, run `identity rotate-password`, save a new file
  on fresh storage.  Limits exposure to key-storage corruption
  over time.
- **Test recovery annually.**  Restore on a scratch device,
  confirm identity_id matches, wipe.  Described in
  [`recovery.md`](recovery.md) §7.
- **Never write the phrase on anything connected to the
  internet.**  Paper only.  Metal backup plates (for
  water/fire/EMP resistance) are a reasonable upgrade for
  paranoia-tier storage, widely available from hardware-wallet
  vendors.

---

## 6. Choosing a password for the encrypted master file

Argon2id with veil's defaults (64 MiB memory, 3 iterations, 4
lanes) is slow: ~100 ms to derive on a laptop.  A 12-character
random password survives about 2^70 guesses in expected wall-clock
terms given a modern GPU cluster — a decade of budget even for a
well-resourced attacker.

- **Good**: 6-word diceware (`correct horse battery staple foo
  bar`).  Easy to remember, ~77 bits of entropy.
- **Better**: 7-8 words.  Adds a decade of breathing room.
- **Do not use**:
  - Passwords you've used elsewhere.
  - Keyboard walks (`qwertyuiop`, `asdfghjkl`).
  - Birthdays, names, anything guessable about you.
  - Anything that autocomplete on your phone ever learned — the
    phone's cloud backup may have learned it too.

Password managers are fine **provided** the password manager
itself is not the same machine as where the encrypted file
lives.  Cross-device hygiene matters.

---

## 7. OpSec for developers using veil

If you're building an app on veil:

- **Never log `identity_sk`, `master_sk`, `app_state_secret`,
  ML-KEM decapsulation seeds, or BIP-39 phrases.**  `Zeroizing`
  wrappers in `veilcore` prevent accidental memory linger;
  don't circumvent them.
- **Don't display the master_seed to users outside the
  `identity create`/`identity show --export-phrase` flows.**
  The CLI's terminal-handling already ensures the phrase isn't
  written to a scrollback log; arbitrary app code might not.
- **Use the encrypted app-state primitive for contact lists
  and profile blobs**, not your own ad-hoc encrypted DHT
  record.  The primitive has reviewed AEAD binding and version
  monotonicity; your ad-hoc version probably doesn't.
- **Respect the safety-number UX.**  Display the fingerprint in
  your contact detail view; surface the "Alice's safety number
  changed" alert on rotation events.  Don't hide it behind a
  debug menu.

---

## 8. What to do if you suspect an active compromise

1. **Physically disconnect** the suspected device from the
   network (pull the cable, disable WiFi).
2. **From a different, trusted device with master_seed
   access**, revoke the compromised device's key.  There is no
   one-shot `identity revoke` CLI yet: revocation is a
   protocol-level operation — add the suspected device's
   `identity_sk` public key to the `IdentityDocument.revoked_keys`
   set, bump `document_version`, re-sign, and re-publish the
   updated `IdentityDocument`.  Re-publish immediately and rely on
   gossip / direct push so the revocation reaches currently-connected
   peers in seconds rather than waiting for the next scheduled
   republish tick.
3. Run `veil-cli identity status`.  Note every anomaly
   reported by the watcher.
4. Revoke any other subkeys the watcher flagged as unauthorised.
5. `veil-cli identity rotate` on the trusted device to
   replace the compromised hot key.
6. Contact your high-value peers out-of-band and let them know
   to expect a safety-number change.
7. Wipe the suspected device and restore fresh.  Do **not**
   reuse it until you're confident how the compromise happened
   (and that the root cause is gone — e.g. a persistent firmware
   implant).

---

## 9. Things we might add later

These are on the roadmap:

- **Shamir Secret Sharing** for master_seed.  Split into N
  paper shares, recoverable from M < N.
- **Hardware-key integration** (YubiKey / secure-enclave) for
  hot `identity_sk`.
- **Duress passwords** for the encrypted master file that
  decrypt to a decoy-but-valid-looking minimal identity.
- **Multi-sig master** (threshold signatures) for paranoid
  rotation policies.

Until those ship, the user-OpSec practices on this page **are**
the defence.

---

## See also

- [`identity-model.md`](identity-model.md) — protocol
  specification.
- [`recovery.md`](recovery.md) — step-by-step recovery
  procedures.
- [`multi-device.md`](multi-device.md) — how multiple devices
  interact.
