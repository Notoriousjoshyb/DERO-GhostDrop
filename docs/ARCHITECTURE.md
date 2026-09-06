# GHOSTDROP V1 — Architecture

One Go codebase, three binaries, one file format, one relay API.

## Binaries

```text
cmd/ghostdrop        desktop: localhost HTTP server + web/ UI + /api/* JSON,
                     opens browser, tray-less, ghost mode, QR, clipboard
cmd/ghostdrop-cli    send / receive / inspect / verify / revoke / list / status / doctor
cmd/ghostdrop-relay  start / status / config / stats  (drop relay server)
```

## Modules (`internal/`)

| Module | Role |
|---|---|
| `crypto` | File keys, `SealFile/OpenFile`, `SealBytes/OpenBytes`, Argon2id KDF + salt, `GenerateDropID`, `Wipe`, `Sha256HexFile`, X25519 wrap/unwrap, Ed25519 sign/verify |
| `manifest` | Drop manifest JSON: ids, hashes, sizes, `files[]`, `storage`, `access`, `payment`, `signature`; `New/Validate/Sign/Verify/EncryptFilenames/CanonicalBytes` |
| `storage` | `Provider` interface (`Put/Get/Delete/Exists/Stat/Health/Backend`); `ErrNotFound/ErrExpired/ErrQuota` |
| `relay` | HTTP ServeMux API (register / PUT resume / GET resume / meta / delete / health / stats), per-drop tokens |
| `dero` | `ResolveName/ValidateAddress/SignWithWallet/VerifyWithPub/WalletStatus/CheckPayment`, `ErrOffline` |
| `config` | `Load()` — OS-native paths + `GHOSTDROP_*` env overrides |
| `database` | SQLite (`modernc.org/sqlite`): `drops/history/contacts` + auto-migrate backup→migrate→verify |
| `platform` | `ConfigDir()/DataDir()/DownloadDir()` OS adapters |
| `drops` | Drop lifecycle orchestration (glues crypto + manifest + storage) |
| `transport`/`p2p` | Transfer plumbing under the relay API |
| `identity`/`wallet`/`payments` | Sender identity, wallet bridge, paid-drop gating |
| `app`/`ui`/`events`/`notifications`/`security` | Desktop/CLI app wiring, UI, events, hardening |

Dependency direction: `drops → crypto + manifest + storage + database`;
`manifest → crypto`; relay/transport depend on storage, never on wallet.
`app` (CLI/desktop core) is self-contained: stdlib + `x/crypto` + `go-qrcode`.

## File format (contract-identical everywhere)

```text
GD01 || headerNonce(24B) || chunks { BE32 len || sealed }*
chunk[i] nonce = headerNonce with last 8 bytes ^= BE64(i)
chunk plaintext size = 1 MiB (last chunk shorter); sealed = XChaCha20-Poly1305
```

Every implementation (crypto package, CLI core, tests) constructs this framing
identically so sealed files are interchangeable.

## Manifest JSON (fields)

`drop_id, version, created_at, expires_at, mode, sender_identity,
recipient_commitment, cipher, payload_hash, payload_size, plaintext_hash,
file_count, files[{name_enc, nonce, size, hash}], storage{backend, ref},
access{wrapped_key, ephem_pub, passphrase_salt, kdf},
payment{amount, address, txid_required}, one_time, signature{by, pub, sig},
chunk_size`. Canonical bytes = fixed-field-order JSON for signing.

## Relay API (exact shapes)

* `POST /api/v1/drops` body `{id,size_bytes,expiry_rfc3339,one_time}` → `{ok}`.
* `PUT /api/v1/drops/{id}/data` octet-stream, `Content-Range: bytes off-end/total`,
  `X-Ghostdrop-Token`. Accepts single-shot and chunked PUTs.
* `GET /api/v1/drops/{id}/data` honors `Range: bytes=off-` (206 resume).
* `GET /api/v1/drops/{id}/meta` → `{id,size_bytes,expiry_rfc3339,one_time[,uploaded_bytes]}`.
* `DELETE /api/v1/drops/{id}` revokes. `GET /api/v1/health`, `GET /api/v1/stats`.

## Data flow

```text
select ──► key (random | X25519-wrap | Argon2id) ──► SealFile (streaming)
  ──► manifest New → Sign → relay POST → PUT chunks (resume) ──► store
  ──► share ghostdrop://drop/<id> (+ key/password out-of-band)
retrieve: meta → GET chunks (resume) → UnwrapFileKey → OpenFile → SHA-256 check
```

Config/history persist via SQLite; ghost mode bypasses persistence entirely.
