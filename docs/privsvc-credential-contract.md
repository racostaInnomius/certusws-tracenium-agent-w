# PrivSvc contract — Infrastructure Gateway credential custody

**Status:** specification, not yet implemented
**Consumer:** `certusws-tracenium-agent-w` (already calls these methods)
**Implementer:** the PrivSvc codebase (not this repo — only the IPC clients live here)
**Context:** [ADR-0001 §(C)](../../certusws-tracenium/docs/adr/ADR-0001-patch-management-gateway.md)

---

## Why PrivSvc owns this

A device with the **Infrastructure Gateway** role holds a vSphere service-account
credential so it can snapshot VMs before patching. Three constraints force that
secret into PrivSvc specifically:

1. **The control plane must never be able to read it.** The admin's browser seals
   the credential against the gateway's public key; the backend only ever relays
   ciphertext it has no key for. Only the holder of the enrollment private key can
   open it — and that is PrivSvc.
2. **PrivSvc already owns the enrollment private key** (`mtls-client.key.pem`, via
   `crypto.csr.generate`). No new key custody is introduced.
3. **Writing to the OS credential store needs privilege.** PrivSvc runs as
   SYSTEM/root; the Node agent does not.

The Node agent calls these methods and holds the plaintext only for the duration
of a single vCenter operation.

---

## Methods

All three follow the existing PrivSvc request/response IPC envelope
(`{ v, id, method, params }` → `{ v, id, result }` or `{ v, id, error: { code, message } }`).

### `credential.provision`

Open a sealed envelope and store the credential.

```jsonc
// params
{
  "ref": "vcenter/default",          // logical key; namespaced, caller-supplied
  "envelope": { /* SealedEnvelope, see below */ }
}
// result
{ "ok": true, "certFingerprint": "5567bc…" }
```

Steps:
1. Reject unless `envelope.v === 1` and `envelope.alg === "RSA-OAEP-256+A256GCM"` → error `unsupported_version`.
2. Compare `envelope.certFingerprint` against the SHA-256 of the **currently
   installed** client certificate. Mismatch → error `stale_envelope`.
3. Unwrap `ek` with the enrollment private key (RSA-OAEP, SHA-256) → 32-byte AES key.
4. AES-256-GCM decrypt `ct` with `iv`, `tag`, and **AAD = the ASCII bytes of
   `certFingerprint`**. Failure → error `decrypt_failed`.
5. Parse the plaintext as `{"username": "...", "password": "..."}` → else `malformed`.
6. Write to the OS credential store under `ref`. Overwrite any existing entry.
7. Zero every intermediate buffer.

### `credential.retrieve`

```jsonc
// params
{ "ref": "vcenter/default" }
// result
{ "username": "svc-tracenium@vsphere.local", "password": "…" }
```

Returns `error.code = "not_found"` when nothing is stored under `ref`.

### `credential.remove`

```jsonc
// params  { "ref": "vcenter/default" }
// result  { "ok": true }
```

Idempotent — removing a non-existent ref succeeds.

### Error codes

| code | Meaning | Agent behaviour |
|---|---|---|
| `not_found` | No credential stored | Reports `classify=no_credential`; terminal |
| `stale_envelope` | Sealed against a rotated certificate | Reports `classify=stale_envelope`; admin must re-enter |
| `decrypt_failed` | Unwrap or GCM authentication failed | Terminal |
| `unsupported_version` | Unknown `v`/`alg` | Terminal |
| `malformed` | Envelope or plaintext shape wrong | Terminal |
| `store_unavailable` | OS credential store inaccessible | Retryable |

`stale_envelope` **must** be distinguishable from `decrypt_failed`. They look
identical cryptographically but mean different things to a human: one says
"re-enter the credential", the other says "something is wrong". The agent maps
them to different UI states.

---

## Envelope format

```jsonc
{
  "v": 1,
  "alg": "RSA-OAEP-256+A256GCM",
  "certFingerprint": "<sha256 hex, lowercase, of the cert DER>",
  "ek":  "<base64url: RSA-OAEP(SHA-256) wrapped 32-byte AES key>",
  "iv":  "<base64url: 12 random bytes>",
  "ct":  "<base64url: AES-256-GCM ciphertext of the JSON credential>",
  "tag": "<base64url: 16-byte GCM authentication tag>"
}
```

**Hybrid, not plain RSA.** RSA-2048 with OAEP-SHA256 can only wrap ~190 bytes; a
long password plus username plus future fields exceeds that. A random AES-256 key
encrypts the payload and RSA wraps only that key.

**All base64url** (RFC 4648 §5: `-`/`_`, no padding) — not standard base64.

**AAD binding.** `certFingerprint` travels in the clear so a stale envelope can be
diagnosed *before* attempting decryption, and is simultaneously bound as GCM
additional authenticated data so it cannot be rewritten without breaking
authentication.

The reference implementation is
[`src/connectors/vcenter/envelope.ts`](../src/connectors/vcenter/envelope.ts)
(`sealCredential` / `openEnvelope`), covered by
[`test/connectors/vcenter-envelope.test.ts`](../test/connectors/vcenter-envelope.test.ts).
The browser will produce the identical wire format via Web Crypto.

---

## Storage requirements

| Platform | Store |
|---|---|
| Windows | Credential Manager (DPAPI, machine scope) |
| macOS | System Keychain, `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` |
| Linux | libsecret when a daemon is present |
| Fallback (any) | AES-256-GCM file, mode `0600`, key derived from enrollment material |

Namespace entries by `ref` so a future second gateway target does not collide.

---

## Security requirements

1. **Never log the plaintext**, nor the envelope's `ct`/`ek`, at any level.
2. **Never return the password in an error message.**
3. **Zero buffers** holding key material and plaintext after use.
4. **Never pass the secret through a shell.** During the Inc 0 spike, `source .env`
   in zsh both corrupted a password (`=`, `$()`, backticks are expanded inside
   values) and leaked a fragment of it into an error message. Read and hand off
   the value in-process only — no shell interpolation, no argv, no env var of a
   child process.
5. `credential.retrieve` is **privileged**: it must only answer the local agent
   over the existing authenticated IPC channel, never anything else.

---

## Generating an interop test vector

Do **not** commit a private key. Generate a fresh throwaway pair locally and
verify your implementation opens an envelope produced by the reference code:

```bash
cd /tmp && openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout k.pem -out c.pem -days 3650 -subj "/CN=gateway-test-vector"
```

```bash
npx tsx -e '
import fs from "node:fs";
import { sealCredential, certFingerprintFromPem } from "./src/connectors/vcenter/envelope";
const cert = fs.readFileSync("/tmp/c.pem","utf8");
const env = sealCredential({ username: "svc@vsphere.local", password: "Test!Vector" }, cert);
console.log("fingerprint:", certFingerprintFromPem(cert));
console.log(JSON.stringify(env, null, 2));'
```

Your `credential.provision` must recover exactly
`{"username":"svc@vsphere.local","password":"Test!Vector"}` from that envelope
using `/tmp/k.pem`. Shape of a real (throwaway) envelope, for reference:

```jsonc
{
  "v": 1,
  "alg": "RSA-OAEP-256+A256GCM",
  "certFingerprint": "5567bcb90a1857135d28c1cb823766f8d7c3e6f892b88f10e12aa44d97ed8829",
  "ek":  "K72kvq8LsOgG77RBov732oeJltduppFL…",   // 342 chars for RSA-2048
  "iv":  "w1DRjyVuNtuTqME3",                     // 16 chars = 12 bytes
  "ct":  "XQH42Q2-C7aNK1_Zgy_R0oaoMhbSneC-…",
  "tag": "dYYU92PDQ8LHWQ_C5w_xgQ"                // 22 chars = 16 bytes
}
```

### Cases your implementation must handle

| Case | Expected |
|---|---|
| Valid envelope, matching cert | credential stored |
| Password with `=`, `$()`, backticks, quotes | byte-exact recovery |
| Payload larger than RSA can wrap (2 KB password) | works — hybrid, not plain RSA |
| Envelope sealed to a different cert | `stale_envelope` |
| One bit flipped in `ct` | `decrypt_failed` |
| `certFingerprint` rewritten | `decrypt_failed` (AAD) |
| `v: 2` | `unsupported_version` |
| `retrieve` with no stored credential | `not_found` |

---

## Status of the consuming side

Already implemented and tested in this repo:

- `src/connectors/vcenter/index.ts` — `makeConnectorDeps()` calls `credential.retrieve`
- `src/priv/ipc-types.ts` — the three methods declared
- `src/transport/grpc-stream.ts` — `vcenter_verify` / `vcenter_snapshot` job dispatch

Until PrivSvc implements these, `credential.retrieve` returns `not_found`, the
gateway reports `vcenter_verify:failed;stage=credential;classify=no_credential`,
and no vCenter connection is attempted. The failure is clean and diagnosable —
but the feature does not work end-to-end.
