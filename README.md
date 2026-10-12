# cypherkit2

A small TypeScript library for encryption and detached signatures using native Web Crypto. It ships ESM JavaScript and TypeScript declarations, has zero runtime dependencies, and uses portable JWK keys and encrypted payloads with binary and standard compact JWE serialization.

All cryptographic functions are asynchronous. Encrypted payload parsing and serialization are synchronous.

> **Pre-release — not independently audited.** Production release requires an independent security review and completion of the runtime/device checks. See [security and release status](docs/security.md).

## Contents

- [Choose an operation](#choose-an-operation)
- [Usage](#usage)
- [Save and restore keys](#save-and-restore-keys)
- [Byte APIs and encoding](#byte-apis-and-encoding)
- [Errors](#errors)
- [Runtime compatibility](#runtime-compatibility)
- [Algorithms and limits](#algorithms-and-limits)
- [Development](#development)

## Choose an operation

| Goal | API | What to retain |
| --- | --- | --- |
| Encrypt with a password | `symmetric.encryptTextWithPassword` | Ciphertext and password |
| Encrypt with a generated shared key | `symmetric.encryptText` | Ciphertext and symmetric key |
| Encrypt for one recipient | `asymmetric.encryptText` | Ciphertext; the recipient keeps their private key |
| Sign a message | `asymmetric.signText` | Exact message, detached signature, and authenticated public signing key |

Encryption returns an immutable `EncryptedData` object. Save its **entire binary envelope** with `.toBinary()` or its **entire JWE string** with `.toJWE()` to decrypt later. There is no recovery without the correct key or password.

## Usage

Import both namespaces from the package root:

```ts
import { symmetric, asymmetric } from 'cypherkit2';
```

Or import only the namespace you need:

```ts
import * as symmetric from 'cypherkit2/symmetric';
import * as asymmetric from 'cypherkit2/asymmetric';
```

The examples below use these namespaces and top-level `await` in an ES module. Consumers use the published JavaScript and declarations; Bun and TypeScript are development tools only.

### Encrypt with a password

Use a strong, randomly generated passphrase. Anyone with the ciphertext can attempt to guess its password offline.

```ts
// Replace this example value with your own randomly generated passphrase.
const password = 'use a randomly generated passphrase here';
const encrypted = await symmetric.encryptTextWithPassword('Hello 🌍', password);
const decrypted = await symmetric.decryptTextWithPassword(encrypted, password);

console.log(decrypted); // Hello 🌍
```

### Encrypt with a shared key

Generate a key once and keep it to decrypt later. Anyone holding the key can encrypt and decrypt messages with it.

```ts
const key = await symmetric.generateKey();
const encrypted = await symmetric.encryptText('Private note', key);
const decrypted = await symmetric.decryptText(encrypted, key);

console.log(decrypted); // Private note
```

See [save and restore keys](#save-and-restore-keys) for portable key storage.

### Encrypt for a recipient

Encrypt with the recipient's authenticated public encryption key. Only their private key can decrypt the message.

```ts
const recipient = await asymmetric.generateEncryptionKeyPair();
const encrypted = await asymmetric.encryptText('For the recipient', recipient.publicKey);
const decrypted = await asymmetric.decryptText(encrypted, recipient.privateKey);

console.log(decrypted); // For the recipient
```

Recipient encryption alone does not identify the sender: anyone with the public key can encrypt to it.

### Sign and verify a message

Signing uses a **separate key pair** from encryption. Authenticate the public signing key independently before relying on a verification result.

```ts
const signer = await asymmetric.generateSigningKeyPair();
const signature = await asymmetric.signText('Exact message', signer.privateKey);
const valid = await asymmetric.verifyText('Exact message', signature, signer.publicKey);

console.log(valid); // true
```

Signatures are detached: store or transmit the original message alongside its signature. Verification checks the exact message bytes.

## Save and restore keys

Ordinary exports return standard JWK objects. **Symmetric and private JWK exports contain unencrypted secrets.** Password-protected exports return `EncryptedData` objects; protected asymmetric exports accept only private keys.

This example exports a public encryption key and creates a protected backup of its private key:

```ts
const recipient = await asymmetric.generateEncryptionKeyPair();
const password = 'use a randomly generated backup passphrase here';

const publicJwk = await asymmetric.exportKey(recipient.publicKey);
const importedPublic = await asymmetric.importEncryptionKey(publicJwk);

const backup = await asymmetric.exportKeyWithPassword(recipient.privateKey, password);
const savedBackup = backup.toJWE();
const recoveredPrivate = await asymmetric.importEncryptionKeyWithPassword(
  asymmetric.EncryptedData.fromJWE(savedBackup), password,
);

const encrypted = await asymmetric.encryptText('Recovered', importedPublic);
console.log(await asymmetric.decryptText(encrypted, recoveredPrivate)); // Recovered
```

Both namespaces provide `exportKey(key)` and `exportKeyWithPassword(key, password)`. Choose the matching import function:

| Key purpose | Import a JWK | Import a password-protected backup |
| --- | --- | --- |
| Symmetric | `symmetric.importKey(jwk)` | `symmetric.importKeyWithPassword(backup, password)` |
| Recipient encryption | `asymmetric.importEncryptionKey(jwk)` | `asymmetric.importEncryptionKeyWithPassword(backup, password)` |
| Signing | `asymmetric.importSigningKey(jwk)` | `asymmetric.importSigningKeyWithPassword(backup, password)` |

Keys are branded native `CryptoKey` values with runtime checks. When importing a dynamically loaded asymmetric JWK, narrow the result with `key.type === 'public'` or `key.type === 'private'` before use.

## Byte APIs and encoding

Use the text helpers for strings and the byte APIs for `Uint8Array` data:

| Operation | Text API | Byte API |
| --- | --- | --- |
| Encrypt with a key, in either namespace | `encryptText(text, key)` | `encrypt(data, key)` |
| Decrypt with a key, in either namespace | `decryptText(encrypted, key)` | `decrypt(encrypted, key)` |
| Encrypt with a password, in `symmetric` | `encryptTextWithPassword(text, password)` | `encryptWithPassword(data, password)` |
| Decrypt with a password, in `symmetric` | `decryptTextWithPassword(encrypted, password)` | `decryptWithPassword(encrypted, password)` |
| Sign, in `asymmetric` | `signText(text, privateKey)` | `sign(data, privateKey)` |
| Verify, in `asymmetric` | `verifyText(text, signature, publicKey)` | `verify(data, signature, publicKey)` |

- Encryption always returns `EncryptedData`; decryption accepts that object. Parse stored data with `EncryptedData.fromBinary(bytes)` or `EncryptedData.fromJWE(string)` first. Text decryption returns a string; byte decryption returns `Uint8Array`.
- Text signatures are unpadded base64url strings. Byte signatures are 64-byte Ed25519 signatures as `Uint8Array`. Verification returns a boolean.
- Text helpers use exact UTF-8: no trimming or normalization, leading BOM preserved, and lone UTF-16 surrogates rejected.
- Input byte views are copied before asynchronous work.

### Serialization and object storage

`EncryptedData` is available from the package root and both namespace subpaths. Its parsers validate the envelope structure and supported parameters; **only decryption authenticates it**. Conversion does not require keys or repeat encryption. Binary output uses a versioned Cipherkit format with raw ciphertext; JWE output uses standard base64url encoding and adds roughly 33% to ciphertext size. The exact authenticated protected header is preserved in both formats.

```ts
import { EncryptedData, symmetric } from 'cypherkit2';

const encrypted = await symmetric.encrypt(imageBytes, key);
const binary = encrypted.toBinary(); // Uint8Array
const jwe = encrypted.toJWE();       // compact JWE string

// uploadUrl and downloadUrl are authorised object-storage URLs.
const upload = await fetch(uploadUrl, {
  method: 'PUT',
  headers: { 'Content-Type': 'application/octet-stream' },
  body: binary,
});
if (!upload.ok) throw new Error('Upload failed');

const download = await fetch(downloadUrl);
if (!download.ok) throw new Error('Download failed');
const restored = EncryptedData.fromBinary(new Uint8Array(await download.arrayBuffer()));
const originalBytes = await symmetric.decrypt(restored, key);

// For text storage instead:
const fromJwe = EncryptedData.fromJWE(jwe);
```

Retain the decryption key securely. Image filenames and MIME types are not automatically included; retain them separately or package them with the plaintext before encryption. A stored encrypted object must be decrypted before it can be displayed as an image. Objects hold no plaintext or secret keys, expose no mutable internal bytes, and return a fresh byte array for each `toBinary()` call. Serialize explicitly before storage or transport; JSON serialization of the object is not an envelope format.

## Errors

Error classes are exported from the package root and extend `CypherkitError`.

| Condition | Result |
| --- | --- |
| Invalid or malformed signature | Verification returns `false` |
| Wrong argument type | `InvalidArgumentError` |
| Invalid key or key purpose | `InvalidKeyError` |
| Required native algorithm unavailable | `CryptoUnavailableError` |
| Wrong secret, malformed ciphertext, or authentication failure | `DecryptionError` |
| Other encryption or signing/verification operation failure | `EncryptionError` or `SignatureError` |

Decryption failures deliberately share the same error. Never use error timing as a secret-validation oracle.

## Runtime compatibility

The target is Node **22.13+ on supported release lines** (CI targets Node 22, 24, and 26), plus modern Chrome/Edge, Firefox, Safari, and iOS Safari with the required native algorithms. Browsers require **HTTPS or localhost**. No cryptographic fallback is loaded.

Support is conditional on the runtime test matrix passing. The recorded local macOS Playwright WebKit 26.6 run fails the required empty-message Ed25519 vector, so signing is explicitly unavailable on that provider and the full runtime release gate remains failing. Playwright WebKit does **not** establish support for shipped Safari.

See the [verification record and remaining release gates](docs/security.md#local-verification-record) for tested environments and outstanding device checks.

## Algorithms and limits

| Operation | Algorithm |
| --- | --- |
| Content encryption | AES-256-GCM with random 96-bit IVs |
| Password encryption | PBES2-HS512+A256KW with 220,000 PBKDF2 iterations |
| Recipient encryption | RSA-OAEP-256 with generated 3072-bit RSA keys and a fresh AES content key |
| Detached signatures | Ed25519 |

Identical plaintexts produce different ciphertexts. There are no algorithm, IV, salt, or iteration options.

- Plaintext and signing input are limited to **16 MiB** per operation.
- Passwords must contain **1–1024 UTF-8 bytes**.
- Operations are one-shot: data is copied; choosing JWE serialization adds base64 storage overhead. Streaming is not supported.
- Authenticated encryption detects changes. The library supplies no secure-messaging protocol, replay prevention, or forward secrecy.

See [wire format and migration examples](docs/format.md) for serialization and import rules, and [security responsibilities](docs/security.md#responsibilities-and-threat-model) for key storage, rotation, and application safeguards.

## Development

From a checkout, install development dependencies with Bun, then check types, build, and run the core tests:

```sh
bun install --frozen-lockfile
bun run typecheck
bun run build
bun test
bun run check:package
```

Run the cross-runtime suite separately:

```sh
bunx playwright install --with-deps chromium firefox webkit
bun run test:runtime
```

Ordinary `bun test` skips the runtime suite. `test:runtime` builds the JavaScript and tests it in actual Node subprocesses and browsers, exchanging artifacts between producers and consumers. The known WebKit signing failure above remains a release blocker.

For manual release checks and password benchmarks, see the [browser harness](tests/runtime/index.html) and [runtime and release gates](docs/security.md#runtime-and-release-gates).
