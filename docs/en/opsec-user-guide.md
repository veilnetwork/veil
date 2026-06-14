# OpSec user guide

**OpSec** — short for *operational security* — is the everyday habits that keep
you safe: how you handle your secret words, your devices, and the people who ask
you for things. This guide covers the parts Veil **cannot** protect you from in
the software itself. Those are on you. The good news: the habits are simple, and
this page walks through each one.

For the protections built into the protocol, see
[`identity-model.md`](identity-model.md). For how to recover after someone breaks
in, see [`recovery.md`](recovery.md).

---

## 1. What Veil *does* defend against

Your *threat model* is simply the list of dangers you're trying to guard
against. Veil's software already handles this side of the list for you:

- Someone quietly listening to your Veil traffic on the wire.
- Bad nodes in the shared directory (the DHT) handing out forged records.
- An attacker who stole one device's secret key (`identity_sk`) trying to
  impersonate your whole identity — the stolen subkey ages out on its own once
  its short `valid_until_unix` window (7 days by default) lapses, so the master
  simply stops re-issuing it.
- An attacker replaying an old, expired delegation, hoping you can't object —
  verifiers reject any key past its `valid_until_unix`, so a stale cert is dead
  on arrival.
- Name squatters trying to grab `@alice` for themselves.
- *Eclipse attacks* — where an attacker surrounds you with nodes they control —
  aimed at hijacking how an `@name` is looked up.

The cryptography under the hood — BLAKE3 preimages, Ed25519 / Falcon-512
signatures, ChaCha20-Poly1305 AEAD, ML-KEM-768 encapsulation, HKDF-SHA256
derivation, rarity-PoW — covers everything in that list, as long as those
algorithms themselves stay unbroken.

---

## 2. What Veil does **NOT** defend against

No software can stop the dangers below. Here the defence is up to you. (Your
identity rests on a *BIP-39 phrase* — a list of 24 ordinary words that *is* your
identity in human-readable form. Anyone who learns those words owns you.)

1. **Someone reading over your shoulder while the words are on screen.** Anyone
   standing behind you when you run `identity create` can photograph the 24 words
   with their phone and rebuild your whole identity.
2. **Phishing — "Veil support needs your phrase."** There is no such support.
   Nobody needs your BIP-39 phrase to help you. If an email, chat message, or
   "tech support" call asks for it, the sender is trying to steal your identity.
3. **Screenshots, camera rolls, or clipboards holding your BIP-39 phrase.** Any
   device that touches the phrase as plain text can leak it.
4. **Keyloggers on the machine you type the phrase into.** A *keylogger* is
   hidden software that records every keystroke. You type the phrase when
   restoring, and it captures it.
5. **Coercion — someone threatening you to hand over your phrase.** Veil has no
   "duress mode" yet, so it can't help you here.
6. **Physical theft of an unlocked device.** The secret key (`identity_sk`) lives
   ready-to-use on the device. If the device is unlocked when it's stolen, the
   thief holds a working key until its short `valid_until_unix` delegation
   window lapses (7 days by default) and the master stops re-issuing it. You
   speed this along by rotating to a fresh subkey, not by broadcasting a
   revocation — there is none.
7. **A tampered Veil program.** If the copy of Veil you run has a hidden backdoor,
   no part of the protocol can save you. Always check the signatures on the files
   you download. (A *signature* is a cryptographic stamp that proves the file
   really came from the Veil developers and wasn't altered.)

---

## 3. Physical-security checklist

### 3.1. While you run `identity create`

☐ **Run it on an offline machine** if you're serious about this. A laptop with
WiFi switched off is a sensible first step. A machine that has *never* touched the
internet (an "air-gapped" machine) is the cautious extreme.

☐ **Dim the screen.** The 24 words can leak through window reflections or over
your shoulder. Turn the brightness down and face a wall.

☐ **No cameras in view.** Glance around before the program shows the phrase.
Phones lying face-up on a table, laptop webcams, ceiling security cameras — any of
them can read the screen if it can see it.

☐ **Write the phrase down by hand, on paper,** before you type the confirmation
words back. The program asks you to retype 3 random words on purpose: it's making
sure you've recorded the phrase somewhere it can't see.

☐ **Put the paper somewhere safe before you close the program.** A fireproof safe,
a safe-deposit box, or a sealed envelope in a spot only you know. The paper
matters more than the laptop.

☐ **Don't photograph, scan, or otherwise digitise the paper** — the one exception
is the built-in encrypted QR backup, which protects the words with a password you
keep on a *different* machine.

### 3.2. Daily use

☐ **Lock the screen whenever you step away.** While Veil is running, your secret
key (`identity_sk`) is loaded and ready to use. A locked screen is your last line
of defence.

☐ **Turn off auto-mount for USB drives.** If a plugged-in drive can run software
on its own, it could drop a keylogger that captures the next phrase you type
during a restore.

☐ **Turn on full-disk encryption on every device.** This stops anyone with
physical access from copying `~/.config/veil/identity.toml` off the disk and
reading it on another machine.

☐ **Treat the encrypted `master.enc` file as only lightly protected.** Its
encryption (Argon2id + ChaCha20-Poly1305) buys you time, not forever, against a
determined attacker who has the file and plenty of GPUs. Protect it with a strong
password — *diceware* (a passphrase built from random dictionary words), 6 words
or more.

### 3.3. Pairing a new device

☐ **Pair in person when you can.** Hold the two screens side by side and check
that the 6-digit confirmation code matches. (This code is shown "out of band" —
*OOB* for short — meaning on the screens themselves, not sent through the
connection you're setting up, so an attacker on that connection can't fake it.)

☐ **If you must pair remotely, compare the code over a channel you already
trust** — a phone call to a number you memorised *before* you needed it, or a
video call where you can both see each other's faces. Do **NOT** compare it over
the same channel you're about to start using: an attacker who controls that
channel could sit in the middle and relay both sides.

☐ **Stop if the codes don't match.** A mismatch means someone is sitting between
you and the other device — a *man-in-the-middle* attack — and the device you're
pairing would become theirs. Stopping is always safe. Confirming anyway is not.

### 3.4. Recovery

☐ **Restore onto a clean device.** Don't restore onto the machine you suspect was
broken into — even if you just got it back from a thief. Buy fresh hardware,
install Veil from files whose signatures you've checked, and restore there.

☐ **After a break-in, run `veil-cli identity show` and inspect the document
yourself.** It prints the current `identity_keys` list and the active
`sig_key_idx`. An attacker may have added a device of their own — to push it
out, rotate to a fresh master-certified subkey from the device that holds your
master seed; the rogue key then ages out within its `valid_until_unix` window.

☐ **Re-verify your safety numbers with the contacts who matter.** A *safety
number* is a code two contacts compare to confirm they're really talking to each
other. After a break-in, your identity keeps the same `identity_id` but gets new
`identity_keys`, so that number changes. Your contacts will see an alert — call
them and re-confirm in person or by voice.

---

## 4. Phishing: the tricks to watch for

*Phishing* is when someone pretends to be trustworthy to talk you out of a secret.
Here are the patterns we expect Veil users to run into.

### 4.1. "Veil support"

An email, direct message, or forum post says: *"Hi, we noticed suspicious activity
on your @alice identity. Please send us your BIP-39 phrase so we can secure it."*

**Never do this.** No support team — present, past, or future — has any reason to
see your phrase. The phrase *is* your identity. Hand it over and you've handed your
identity over.

### 4.2. A fake restore screen

A fake program or website asks you to "paste your phrase here to verify you still
control the identity."

**Never do this either.** The only place it's ever right to type your BIP-39
phrase is into the real `veil-cli identity restore` command, on a machine you
trust. Nowhere else.

### 4.3. A hijacked QR scan while pairing

While you pair two devices, an attacker's app intercepts the QR scan and shows a
fake confirmation code. Here's why the design protects you: the real code appears
on the source device (the one holding your `master_seed`), and the new device
shows the same code, computed from the genuine shared key of that pairing session.
An attacker sitting in the middle can't make their fake stand-in display the
source's code.

What this means for you: **always compare the codes with your own eyes** before
you tap "confirm" on the source device. The whole safety of pairing rests on this
one step.

### 4.4. A look-alike name

An attacker registers `@a1ice` — with the digit one in place of the letter "l" —
hoping you won't notice. Or they try swapping the Latin "a" for the Cyrillic
letter at Unicode U+0430, which looks identical.

How the protocol helps: Veil only allows plain ASCII letters in names and blocks
Unicode characters entirely, so the Cyrillic look-alike is rejected outright.
`@a1ice`, though, is a perfectly valid name that just *looks* like yours — so
**check the spelling of any handle before you add it as a contact**. The safety
number settles all doubt: two names that look alike have completely different
60-digit fingerprints. (A *fingerprint* is a short code derived from someone's
keys — if two fingerprints differ, the keys differ, full stop.)

### 4.5. "Please confirm by reading me your safety number"

Genuine safety-number checking means **you read** the 60 digits *to* your contact
over a trusted channel — never the other way around. If they read the number to
you instead, an attacker can feed you their own fake number and trick you into
confirming it.

---

## 5. Looking after your backups

- **Keep several paper copies in different places.** One in your home safe, one
  with a family member or a lawyer. A house fire destroys one copy; a legal
  seizure takes another; spreading them across 3 locations survives any single
  mishap.
- **Refresh the encrypted file once a year.** Re-run `veil-cli identity restore`
  with your BIP-39 phrase and accept the "Overwrite existing encrypted master
  file?" prompt to rewrite `master.enc` under a fresh password, then save it on
  fresh storage. (There is no `identity rotate-password` subcommand; the restore
  flow is how you re-key the master file.) This limits how long any single
  stored copy is exposed to slow decay or corruption.
- **Test your recovery once a year.** Restore onto a spare device, confirm the
  `identity_id` matches, then wipe that device clean. The steps are in
  [`recovery.md`](recovery.md) §7.
- **Never write the phrase on anything connected to the internet.** Paper only.
  Metal backup plates — which survive water, fire, and electrical surges better
  than paper — are a reasonable upgrade if you want extra resilience; the same
  vendors who sell hardware wallets sell them.

---

## 6. Choosing a password for the encrypted master file

Veil deliberately makes this password slow to test. With its defaults (Argon2id,
64 MiB memory, 3 iterations, 4 lanes) each guess takes about 100 ms on a laptop.
A 12-character random password then stands up to roughly 2^70 guesses in real
elapsed time even against a modern cluster of GPUs — that's a decade of effort for
a well-funded attacker. So pick a good one:

- **Good**: 6-word diceware (`correct horse battery staple foo bar`). Easy to
  remember, with about 77 bits of *entropy* — a measure of how hard it is to
  guess.
- **Better**: 7 or 8 words. Buys another decade of breathing room.
- **Don't use**:
  - A password you've used anywhere else.
  - Straight rows across the keyboard (`qwertyuiop`, `asdfghjkl`).
  - Birthdays, names, or anything someone could guess about you.
  - Anything your phone's autocomplete has ever learned — your phone's cloud
    backup may have learned it too.

Password managers are fine, **as long as** the manager doesn't live on the same
machine as the encrypted file. Keeping the two apart on separate devices is what
matters.

---

## 7. OpSec for developers building on Veil

If you're writing an app on top of Veil:

- **Never log `identity_sk`, `master_sk`, `app_state_secret`, ML-KEM decapsulation
  seeds, or BIP-39 phrases.** The `Zeroizing` wrappers in `veilcore` scrub these
  from memory once they're done with; don't work around them.
- **Don't show the `master_seed` to users outside the `identity create` flow.**
  That is the only place the 24-word phrase is ever displayed — `identity show`
  prints just the public document (it takes only `--veil-dir`; there is no
  `--export-phrase` flag), and the encrypted master-seed backup goes out through
  `identity export-qr-backup`, never as plaintext. The CLI is careful not to
  leave the phrase in your terminal's scroll-back history; your own code might
  not be.
- **Store contact lists and profile data with the built-in encrypted app-state
  feature**, not a hand-rolled encrypted DHT record of your own. The built-in one
  has been reviewed — it binds the data correctly and won't let an old version be
  swapped back in. Your hand-rolled version probably hasn't been.
- **Honour the safety-number experience.** Show the fingerprint in your
  contact-details view, and surface the "Alice's safety number changed" alert
  whenever keys rotate. Don't bury it in a debug menu.

---

## 8. What to do if you think someone has broken in right now

Work through these in order:

1. **Cut the suspected device off from the network.** Pull the cable, switch off
   WiFi — physically disconnect it.
2. **From a different device you trust — one with access to your `master_seed` —
   stop endorsing the compromised device's key.** There is no `identity revoke`
   command and no revocation mechanism: a delegation cannot be cancelled, only
   left to expire. From the device that holds the master seed, run
   `veil-cli identity rotate` to mint a fresh master-certified subkey and point
   the active `sig_key_idx` at it, then re-publish the updated
   `IdentityDocument`. Re-publish right away and lean on gossip / direct push so
   the fresh document reaches the peers you're connected to within seconds. The
   compromised subkey ages out on its own once its `valid_until_unix` (7 days by
   default) passes, since the master stops re-issuing it.
3. **Run `veil-cli identity show`** and read off the `identity_keys` list and the
   active `sig_key_idx`. Note any subkey or pairing you don't recognise.
4. **Stop re-issuing any other subkeys you don't recognise** — they too age out
   within their `valid_until_unix` window once the master no longer renews them.
5. **Reach your most important contacts through some other channel** and warn them
   that your safety number is about to change.
6. **Wipe the suspected device and restore from scratch.** Do **not** use it again
   until you understand how the break-in happened and you're sure the cause is
   gone — for example, malware buried in the device's firmware that survives a
   normal wipe.

---

## 9. Things we may add later

These are on the roadmap, not here yet:

- **Shamir Secret Sharing** for the `master_seed` — split it into N paper shares
  where any M of them (with M < N) can rebuild it, so losing a few is survivable.
- **Hardware-key support** (YubiKey / secure enclave) for the live `identity_sk`,
  keeping it off the main disk entirely.
- **Duress passwords** for the encrypted master file: a second password that opens
  a believable but harmless decoy identity, for when you're forced to unlock.
- **Multi-signature master** (threshold signatures) so the most cautious users can
  require several keys to approve a rotation.

Until those land, the habits on this page **are** your defence.

---

## See also

- [`identity-model.md`](identity-model.md) — protocol
  specification.
- [`recovery.md`](recovery.md) — step-by-step recovery
  procedures.
- [`multi-device.md`](multi-device.md) — how multiple devices
  interact.
