# GHOSTDROP V1 — Known Limitations

Honest boundaries. Nothing here is secret; all of it is accepted V1 scope.

1. **Sizes and timing leak.** No padding, cover traffic, or mixing. Anyone
   watching the relay (or the network) can correlate uploads to downloads by
   size and time.
2. **Relay trusted for availability.** A malicious relay cannot *read* drops
   but can delete them, refuse them, or go offline. No replication or
   federation in V1.
3. **Passwords are only as strong as chosen.** Argon2id (64 MiB / 3 iters)
   raises guessing cost; `password123` still falls. Prefer recipient-key mode
   for anything sensitive.
4. **No malware handling.** Received bytes are written faithfully. Scan and
   open with care — especially executables and documents with macros.
5. **DERO needs connectivity.** Names, wallet signing, and payment checks
   fail closed offline (`ErrOffline`). No cached-trust fallbacks.
6. **No forward secrecy rotation.** Per-drop keys limit blast radius, but a
   compromised recipient key reads every drop ever sent to it. Rotate keys
   by generating new ones; V1 offers no automatic rotation.
7. **Classical crypto only.** X25519/Ed25519 are not post-quantum.
8. **Local device is trusted.** Disk encryption, screen lock, and OS hygiene
   are the user's job; memory `Wipe` cannot stop a live attacker.
9. **Single-recipient drops.** One wrapped key per manifest; group sends are
   repeated single sends in V1.
10. **1 GiB+ transfers are slow-start proofed, not optimized.** Resume works,
    but there is no parallel chunk upload or delta sync yet.
11. **Desktop is localhost-bound.** The GUI serves `web/` on loopback only;
    remote access to the desktop server is not a supported configuration.
