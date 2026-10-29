# superapp-demo-node-lite

English | [中文](README.zh-CN.md)

Minimal Node.js implementation (HMAC-SHA256 signature verification + AES-256-GCM decryption): only `POST /user/checkUser`. Zero dependencies, Node >= 18 (Node 20+ LTS recommended).

## Project Structure

| File | Purpose |
|---|---|
| `src/server.js` | HTTP server and the checkUser flow: verify signature → parse body → decrypt → business |
| `src/signature.js` | `TC-Signature` verification (protocol, do not change) |
| `src/identityCrypto.js` | `encryptedData` decryption (protocol, do not change) |
| `src/userStore.js` | User lookup and openId mapping storage (**replace with your own**) |
| `src/errorCodes.js` | All `returnCode` values |
| `checkUser.json` | OpenAPI 3.0 spec of `/user/checkUser`, importable into Swagger / Postman |

## To Replace When Integrating

`src/userStore.js` is an in-memory demo. Keep the two async functions and back them with your own storage:

- `findUser(userId)`: look up the user in your own user store; return `true` / `false`. The demo reads users from `USERS`.
- `saveOpenIdMapping({ openId, miniAppId, userId })`: persist the `openId + miniAppId ↔ userId` mapping (openId + miniAppId is a unique composite key, upsert on conflict). Called only when the user exists and `encryptedData` was decrypted with a non-empty `openId` and `miniAppId`.

If either function throws, the server returns `50000`. Any other unexpected error also returns `50000` without crashing the process.

## Run

```bash
SIGN_KEY=0123456789abcdef0123456789abcdef \
DATA_ENCRYPT_KEY=0123456789abcdef0123456789abcdef \
USERS=demo-user-001 npm start     # listens on :9093 by default
npm test
```

On Windows (PowerShell):

```powershell
$env:SIGN_KEY="0123456789abcdef0123456789abcdef"
$env:DATA_ENCRYPT_KEY="0123456789abcdef0123456789abcdef"
$env:USERS="demo-user-001"
npm start
```

At startup the server prints a warning if `SIGN_KEY` or `DATA_ENCRYPT_KEY` is missing or has the wrong length.

> The keys above are the public test-vector keys used by `npm test`. In production, use the same keys you entered in the console (see [Console Configuration](#console-configuration)), keep `SIGN_KEY` and `DATA_ENCRYPT_KEY` different, and keep them out of source control.

| Environment variable | Description |
|---|---|
| `SIGN_KEY` | HMAC signing key, 32–255 bytes (console: **Signing key**) |
| `DATA_ENCRYPT_KEY` | AES-256-GCM data key, exactly 32 bytes (console: **Data encryption key**) |
| `APPLICATION_ID` | Optional, pins `TC-ApplicationID` (console: **AppID**) |
| `BASE_PATH` | Optional, the path part of the console **Domain name** (see [Request Path](#request-path)). Default empty: serves `/user/checkUser` |
| `SIGNATURE_SKEW_SEC` | Timestamp window in seconds, default 300 |
| `USERS` | Your real app user IDs for testing, comma-separated. A request `userId` in this list returns `true`, otherwise `false` |

## Console Configuration

In the console, go to **Configuration management → Backend service configurations** and add a backend service domain:

| Console field | Used as | Notes |
|---|---|---|
| AppID | `TC-ApplicationID` header / `APPLICATION_ID` | Shown by the console, e.g. `app-xxxxxxxx`. It is part of the signature (line 5 of StringToSign). |
| Signing key | `SIGN_KEY` | Entered by you. HMAC-SHA256 key, 32–255 bytes. |
| Data encryption key | `DATA_ENCRYPT_KEY` | Entered by you. AES-256-GCM key, exactly 32 bytes. |
| Domain name | Where the platform sends `POST <Domain name>/user/checkUser` | May include a path, see [Request Path](#request-path). |

Both keys are chosen by you, so generate them randomly and configure the **same values** in the console and on your server. For example:

```bash
openssl rand -hex 32   # Signing key: 64 hex chars = 64 bytes
openssl rand -hex 16   # Data encryption key: 32 hex chars = 32 bytes
```

The keys are used as their UTF-8 bytes, so a 32-character ASCII string is exactly 32 bytes. Avoid non-ASCII characters.

## Request Path

The platform calls `<Domain name>/user/checkUser`. The **signed path** is that full URL without `scheme://host`:

**signed path = path part of the console Domain name + `/user/checkUser`**

| Domain name in the console | Platform requests | Signed path | `BASE_PATH` |
|---|---|---|---|
| `https://api.example.com` | `https://api.example.com/user/checkUser` | `/user/checkUser` | not set (default) |
| `https://api.example.com/superapp` | `https://api.example.com/superapp/user/checkUser` | `/superapp/user/checkUser` | `/superapp` |
| `https://api.example.com/superapp/inner` | `https://api.example.com/superapp/inner/user/checkUser` | `/superapp/inner/user/checkUser` | `/superapp/inner` |

A path in the Domain name is optional and can be anything you like; `/superapp/inner` in this document is only an example.

### Gateway Forwarding

If the Domain name points to a gateway and the gateway **strips the prefix** when forwarding, your server receives `/user/checkUser`, but the signature was computed over the full path. Use either option:

1. Configure the gateway to forward the path unchanged; or pass the original request path in a custom header (e.g. `X-Original-URI`) and use it for verification.
2. Configure the prefix on your server (e.g. `/superapp/inner`) and verify with `prefix + received path` as the path.

This demo verifies with the path it actually receives, so it supports forwarding the path unchanged (set `BASE_PATH` to the prefix). For the other approaches, pass the original / rebuilt path as `requestURI` to `buildHmacStringToSign` in `src/signature.js`.

The gateway must not rewrite the body or the query, and must keep the `TC-*` headers.

## Request

Headers:

```
TC-Signature:     signature (64 lowercase hex chars)
TC-Timestamp:     13-digit millisecond timestamp
TC-ApplicationID: application ID
TC-TraceID:       trace ID, echoed back as requestId
```

Body:

```json
{
  "userId": "u1",
  "encryptedData": {
    "algorithm": "AEAD_AES_256_GCM",
    "ciphertext": "base64(ciphertext || tag)",
    "nonce": "base64(12B)"
  }
}
```

- `userId`: your own user ID (the uid the Super App sets via `setAccount`).
- `encryptedData`: the encrypted identity, see [Part 2](#part-2-decrypt-encrypteddata). It is optional; when absent, no identity is decrypted. The identity (`openId` / `miniAppId`) is only carried in this field.

## Part 1: Verify the Signature

Before sending a request, the platform computes the signature with the rules below and puts it in the `TC-Signature` header. When your server receives the request, it recomputes the signature from what it received using **the same rules** (steps 3–7) and compares it with `TC-Signature` (step 8). A match means the request came from the platform and was not tampered with.

```
TC-Signature = lowercase_hex( HMAC-SHA256( key = SIGN_KEY, message = StringToSign ) )
```

**Step 1: Read the headers**

Read `TC-Signature`, `TC-Timestamp` and `TC-ApplicationID`. If the signature headers are missing, return `40101`.

**Step 2: Check the timestamp**

`TC-Timestamp` must be 13-digit milliseconds and within `SIGNATURE_SKEW_SEC` (default 300 seconds) of the current time, otherwise return `40102`.

**Step 3: Prepare the inputs**

| Input | Source |
|---|---|
| `method` | HTTP method, upper case, e.g. `POST` |
| `path` | The full path the platform called, see [Request Path](#request-path). Keep it as is: do not decode it and do not resolve `.` or `..` |
| `query` | The part of the URL after `?`; `/user/checkUser` normally has no query |
| `applicationId` | Request header `TC-ApplicationID` |
| `timestamp` | Request header `TC-Timestamp`, used as received |
| `body` | **The raw request body bytes as received.** Do not parse the JSON and re-serialize it |
| `SIGN_KEY` | The Signing key configured in the console |

**Step 4: Normalize the query**

If there is no query, `canonicalQuery` is an empty string; go to the next step. Otherwise:

1. Split on `&` into `key=value` pairs (if `=` is missing, the value is an empty string).
2. **URL-decode** each key and value (`+` stays a literal plus, not a space; invalid `%XX` or invalid UTF-8 is a failure), then **URL-encode** it again (keep `A-Z a-z 0-9 - _ . ~`, write every other UTF-8 byte as uppercase `%XX`, space becomes `%20`).
3. Sort by key in byte order; for equal keys, sort by value.
4. Join with `&` to get `canonicalQuery`.

Example: `?name=%E5%BC%A0%20%E4%B8%89&b=2&a=1&a=0` → `a=0&a=1&b=2&name=%E5%BC%A0%20%E4%B8%89`

**Step 5: Compute the body hash**

```
bodyHash = lowercase_hex( SHA-256( body ) )
```

The hash of an empty body is `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

**Step 6: Build StringToSign**

Exactly 7 lines joined with `\n`, **plus a trailing `\n`**:

| Line | Content |
|---|---|
| 1 | `TC-SIGN-V1:P2S` (fixed value) |
| 2 | `method` |
| 3 | `path` |
| 4 | `canonicalQuery` (an empty line if there is no query; **the line is still present**) |
| 5 | `applicationId` |
| 6 | `timestamp` |
| 7 | `bodyHash` |

```
StringToSign = "TC-SIGN-V1:P2S\n" + method + "\n" + path + "\n" + canonicalQuery + "\n"
             + applicationId + "\n" + timestamp + "\n" + bodyHash + "\n"
```

**Step 7: Compute the signature**

```
signature = lowercase_hex( HMAC-SHA256( SIGN_KEY, StringToSign ) )   // 64 lowercase hex chars
```

**Step 8: Compare**

Compare `signature` with the `TC-Signature` header in constant time. Only 64-char lowercase hex is accepted. If they match, verification passes; otherwise return `40101`.

### Code (full implementation in `src/signature.js`)

```js
import crypto from 'node:crypto';

function sign({ secret, method, path, canonicalQuery, applicationId, timestamp, body }) {
  const bodyHash = crypto.createHash('sha256').update(body).digest('hex');
  const stringToSign = [
    'TC-SIGN-V1:P2S', method, path, canonicalQuery, applicationId, timestamp, bodyHash,
  ].join('\n') + '\n';
  return crypto.createHmac('sha256', secret).update(stringToSign).digest('hex');
}
```

### Test Vector

`/superapp/inner` below is only an example prefix; your signed path depends on your console Domain name.

| Item | Value |
|---|---|
| SIGN_KEY | `0123456789abcdef0123456789abcdef` |
| Request | `POST /superapp/inner/user/checkUser`, no query |
| TC-ApplicationID | `app-demo001` |
| TC-Timestamp | `1721234567890` |
| Body | `{"userId":"user-001","encryptedData":{"algorithm":"AEAD_AES_256_GCM","ciphertext":"VsfUDLx2m8iK5lPRJL+XPJNFdsZ28yvGEqzD1ol0lf7zwWF7GoN4Mr0H1jW0xYJKXKL50zKS+KtGKhkqeXZwTp0zRkyqUHz7FpxuQy1JTZh+LJDU","nonce":"AAECAwQFBgcICQoL"}}` |
| bodyHash | `de5522bc02375469f4577ad87e0a0d2ff95449282b6de8231b8dea5fba7dc538` |
| StringToSign | `TC-SIGN-V1:P2S\nPOST\n/superapp/inner/user/checkUser\n\napp-demo001\n1721234567890\nde5522bc02375469f4577ad87e0a0d2ff95449282b6de8231b8dea5fba7dc538\n` |
| TC-Signature | `979d739e66a1e2709f855e829f50d146ac825e6c140dbef3a1df4cdbe042f59f` |

## Part 2: Decrypt encryptedData

**Step 1: Read the fields**

Read `algorithm`, `ciphertext` and `nonce` from `encryptedData` in the body. `algorithm` must be `AEAD_AES_256_GCM`; any other value is rejected. This is only the protocol identifier: the cipher is standard AES-256-GCM.

**Step 2: Base64-decode**

`ciphertext` and `nonce` are standard Base64 (not URL-safe). The decoded `nonce` is 12 bytes, random for every request.

**Step 3: Split ciphertext and tag**

The last 16 bytes of the decoded `ciphertext` are the GCM tag; the rest is the ciphertext.

**Step 4: AES-256-GCM decrypt**

- key: `DATA_ENCRYPT_KEY` (32 bytes)
- iv: the decoded `nonce`
- tag: the 16 bytes from step 3
- **No AAD** (not passing it, `nil`, an empty string, or a zero-length byte array all give the same result; passing any non-empty AAD will fail authentication)

**Step 5: Parse the plaintext**

The plaintext is JSON: `{"openId":"...","miniAppId":"..."}`.

```js
import crypto from 'node:crypto';

function decryptEncryptedData(env, key /* 32-byte Buffer */) {
  const sealed = Buffer.from(env.ciphertext, 'base64');
  const nonce = Buffer.from(env.nonce, 'base64');
  const d = crypto.createDecipheriv('aes-256-gcm', key, nonce);
  d.setAuthTag(sealed.subarray(sealed.length - 16));
  const plain = Buffer.concat([d.update(sealed.subarray(0, sealed.length - 16)), d.final()]);
  return JSON.parse(plain.toString('utf8'));   // { openId, miniAppId }
}
```

Full implementation (with input validation) in `src/identityCrypto.js`. Any decryption failure returns `40101`.

### Test Vector

| Item | Value |
|---|---|
| DATA_ENCRYPT_KEY | `0123456789abcdef0123456789abcdef` |
| nonce | `AAECAwQFBgcICQoL` |
| ciphertext | `VsfUDLx2m8iK5lPRJL+XPJNFdsZ28yvGEqzD1ol0lf7zwWF7GoN4Mr0H1jW0xYJKXKL50zKS+KtGKhkqeXZwTp0zRkyqUHz7FpxuQy1JTZh+LJDU` |
| Plaintext | `{"openId":"oUpF8uMuAJO_M2pxb1Q9zNjWeS6o","miniAppId":"mini-demo001"}` |

## Response

`{"returnCode":"0","returnMessage":"OK","data":true|false,"requestId":"..."}`

`requestId` echoes `TC-TraceID` (a random ID is generated if it is absent).

| Scenario | returnCode | data |
|---|---|---|
| User exists | `"0"` | `true` |
| User does not exist (business result, not a failure) | `"0"` | `false` |
| Invalid parameter / missing `userId` | `"40001"` | `null` |
| Signature invalid / identity decryption failed | `"40101"` | `null` |
| Timestamp expired | `"40102"` | `null` |
| Local `SIGN_KEY` / `DATA_ENCRYPT_KEY` not configured / internal error | `"50000"` | `null` |

## Troubleshooting

| Symptom | Cause |
|---|---|
| `404 not found` | The request path is not `<BASE_PATH>/user/checkUser`; set `BASE_PATH` to the path part of the console Domain name |
| Always `40101` | The body was re-serialized by the framework, so the hash does not match the raw bytes |
| Always `40101` behind a gateway / proxy | The gateway stripped or changed the path prefix; see [Gateway Forwarding](#gateway-forwarding) |
| Line 4 missing | The empty line was dropped when there is no query, so StringToSign is one `\n` short |
| Missing trailing `\n` | The last line of StringToSign must also end with `\n` |
| Signature case mismatch | Only lowercase hex is accepted |
| `40102` | Clock skew exceeds the window, or the timestamp is not 13-digit milliseconds |
| Signature fails when the query contains `+` | `+` is a literal plus, not a space; it must be encoded as `%2B` |
| `40101 identity decrypt failed` | `DATA_ENCRYPT_KEY` differs from the one in the console, or `algorithm` is not `AEAD_AES_256_GCM` |
| `50000 server misconfigured` | `SIGN_KEY` is not 32–255 bytes, or `DATA_ENCRYPT_KEY` is not exactly 32 bytes; check the startup warnings |

## API Spec (checkUser.json)

`checkUser.json` is an OpenAPI 3.0 description of `POST /user/checkUser`: headers, request body, field rules and an example for every `returnCode`. Use it as the interface reference when implementing your own endpoint.

- **Swagger**: open it in [Swagger Editor](https://editor.swagger.io) (File → Import file) or any Swagger UI.
- **Postman**: Import → select `checkUser.json`. Set the `host` / `basePath` server variables to your service.

`TC-Signature` must be computed for every request from the current timestamp, path and raw body, so the example request cannot be sent as-is: its timestamp is outside the window and returns `40102`. To check the full flow locally, run `npm test`.
