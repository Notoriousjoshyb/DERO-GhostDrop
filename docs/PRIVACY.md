# GHOSTDROP V1 — Privacy

Who sees what. The rule: **plaintext and keys exist only on sender and
recipient devices.** Everything else sees ciphertext, sizes, and timing.

## Per-component visibility

| Component | Plaintext | Filenames | Keys / seeds / tokens | Metadata seen |
|---|---|---|---|---|
| Sender device | ✅ yes (own files) | ✅ yes | ✅ file key in RAM only | everything, locally |
| Relay server | ❌ ciphertext only | ❌ encrypted in manifest | ❌ never | drop id, size, timing, expiry, endpoints |
| Storage backend | ❌ ciphertext only | ❌ | ❌ never | ref, size, expiry |
| Network observer | ❌ | ❌ | ❌ | sizes, timing, endpoints |
| Recipient (after auth) | ✅ yes | ✅ yes | file key only | own drops |
| DERO network | ❌ no file data ever | ❌ | ❌ | only intentional txs (name lookups, payments) |
| Logs (relay + clients) | ❌ never | ❌ never | ❌ never | ids, sizes, status codes |

## Notes per component

* **Sender.** Plaintext is read from disk, sealed in 1 MiB streaming chunks,
  hashed (SHA-256) for integrity. The file key is generated with
  `crypto/rand`, held in memory, locked (X25519) or derived (Argon2id), then
  `Wipe`d. Nothing plaintext leaves the process except to the recipient's key.
* **Relay.** Receives `PUT` ciphertext + `POST` registration
  (`{id,size_bytes,expiry_rfc3339,one_time}`). Enforces expiry, tokens
  (`X-Ghostdrop-Token`), and one-time consumption. Never sees keys; never
  logs content/keys. Honest-but-curious relay learns *that* a drop of size N
  moved at time T — accepted V1 leakage (see THREAT_MODEL correlation).
* **Storage.** The `storage.Provider` interface passes opaque bytes. Backends
  MUST NOT interpret payload; `Get` offset exists only for resume.
* **Recipient.** Sees nothing until `UnwrapFileKey` succeeds (private key or
  passphrase) — then plaintext + filenames. Pre-auth, a recipient is just an
  observer.
* **DERO.** Only what you do on purpose: resolving `captain.dero`-style names,
  signing with a wallet, checking a payment tx. Free anonymous drops touch no
  DERO endpoint at all. Offline → `ErrOffline`, never a silent fallback.
* **Desktop / CLI.** Local history (drop ids, contacts) lives in the OS-native
  config dir; ghost mode (`--ghost`) persists nothing. Clipboard copy and QR
  share move the *link*, never the key, unless the user explicitly copies it.

## What is intentionally NOT hidden in V1

Drop sizes, upload/download timing, relay endpoints, and (for paid/named
flows) the DERO transactions the user chose to make. See
[THREAT_MODEL.md](THREAT_MODEL.md) and [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).
