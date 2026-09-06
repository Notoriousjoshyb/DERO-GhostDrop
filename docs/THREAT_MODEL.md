# GHOSTDROP V1 — Threat Model

Honest scope: what Ghostdrop protects, and what it does not. Read this before
trusting the system with anything that matters.

## Attackers considered

1. **Malicious sender** — ships a drop crafted to harm the recipient.
2. **Malicious recipient** — tries to read drops not meant for them, or to
   re-share / retain after expiry.
3. **Malicious relay** — reads, modifies, replays, drops, or fabricates stored
   bytes; lies about health/stats; logs everything it sees.
4. **Malicious storage backend** — same as relay, plus disk forensics.
5. **Passive network observer** — sees packets (sizes, timing, endpoints)
   between sender/recipient and relay. Cannot break TLS assumptions beyond
   what is stated; sees everything metadata-level on plain HTTP relays.
6. **Compromised DERO node / wallet endpoint** — returns false names,
   fake payment confirmations, or harvests messages sent for signing.
7. **Stolen link** — attacker gets `ghostdrop://drop/<id>` (but not the key).
8. **Malicious file** — the *content* itself is hostile (malware, exploit).
9. **Traffic-correlation analyst** — links senders to recipients via
   timing/size patterns across drops.
10. **Local-device thief** — steals an unlocked/locked sender or recipient
    machine, or reads its disk.

## PROTECTS against

* **Content confidentiality vs relay / storage / observer.** Files are sealed
  on-device with a fresh XChaCha20-Poly1305 key before upload. These parties
  see ciphertext, sizes, timing — never plaintext, filenames, or keys.
* **Content integrity.** Any modification (bit flip, truncation, splice) fails
  authentication at chunk granularity; the recipient gets an error, not
  corrupted output. Partial plaintext is discarded.
* **Wrong-recipient disclosure.** The file key is wrapped to the recipient's
  X25519 public key (or a passphrase-derived key). A stolen link *alone* does
  not decrypt; `UnwrapFileKey` with the wrong private key fails.
* **Sender authenticity (when signed).** Ed25519 manifest signatures
  (`crypto.Sign/Verify`, `manifest.Sign/Verify`) bind drop metadata to a
  sender key. Unsigned/anonymous drops are explicitly marked as such.
* **Replay of expired / revoked drops.** `expires_at` is enforced server-side
  and re-checked client-side; `DELETE` removes ciphertext + manifest; one-time
  drops are consumed on first successful retrieval.
* **Passphrase guessing cost.** Argon2id (64 MiB, 3 iterations) makes each
  guess expensive. (It does not save `password123` — see below.)
* **Key/secret leakage via logs.** The codebase never logs keys, seeds, or
  tokens; the relay logs IDs, sizes, and status codes only. Covered by
  acceptance check "no secrets in logs".

## DOES NOT protect against

* **Size / timing hiding.** No padding, no mixing, no cover traffic in V1.
  A correlation analyst *can* match a 64 MiB upload to a 64 MiB download.
* **Malicious files.** Ghostdrop transports bytes faithfully — including
  malware. There is no sandbox, no AV scan, no file-type firewall. Open
  received files with the same care as any download.
* **Endpoint compromise.** A rooted sender/recipient device, a keylogger, or
  a compromised OS sees plaintext and keys. Memory `Wipe` limits lifetime,
  not a live attacker.
* **Weak passphrases.** Argon2id slows guessing; it cannot fix `qwerty`.
  High-value drops MUST use recipient-key mode, not passwords.
* **Availability.** A malicious relay can delete drops, refuse uploads, or go
  offline. It cannot read them — but it can deny them.
* **Shoulder-surfed / forwarded keys.** Anyone holding both the link *and*
  the key (or passphrase) reads the drop until expiry/revocation. Forward
  keys only over a channel you trust.
* **Compromised wallet/daemon answers.** `CheckPayment` / `ResolveName`
  against a hostile endpoint can lie. V1 surfaces `verified` flags and
  `ErrOffline`; it does not cross-check nodes.
* **Global passive adversary with relay + network view.** Treated as the
  correlation analyst above: confidentiality of *content* holds, anonymity of
  *who-sent-to-whom* does not.
* **Post-quantum secrecy.** X25519 / Ed25519 are not post-quantum. A future
  quantum adversary with recorded ciphertext is out of V1 scope.
