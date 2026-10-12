# Wire format and portability

The library implements a restricted subset of [JWE Compact Serialization (RFC 7516)](https://www.rfc-editor.org/rfc/rfc7516.html) and [JWA (RFC 7518)](https://www.rfc-editor.org/rfc/rfc7518.html). Standard keys use [JWK (RFC 7517)](https://www.rfc-editor.org/rfc/rfc7517.html). It is not a general JOSE processor.

Five dot-separated, canonical unpadded base64url segments: protected header, encrypted key, IV, ciphertext, authentication tag. Only the following suites are accepted:

| alg | enc | Encrypted key |
| --- | --- | --- |
| dir | A256GCM | empty |
| RSA-OAEP-256 | A256GCM | 384 or 512 bytes; must match RSA modulus |
| PBES2-HS512+A256KW | A256GCM | 40 bytes |

AES-GCM uses a fresh 12-byte IV, 32-byte content key and 16-byte tag. The original encoded protected header is the authenticated data. Empty plaintext has an empty ciphertext segment and a nonempty authentication tag. The called API determines the expected algorithm.

Headers must be JSON objects with only `alg`, `enc`, optional password parameters `p2s`/`p2c`, and the protected-key content type described below. Unknown headers (including `crit`, `zip`, trusted keys, URLs, and algorithm extensions) are rejected. Duplicate members use the last member, consistently through `JSON.parse`, as allowed by RFC 7516 section 4. Header JSON is never reserialized for authentication. Ordinary ciphertext APIs reject `cty`; protected key APIs require exactly `cty: "jwk+json"`.

Password encryption emits `p2c: 220000` and a fresh 32-byte salt input encoded in `p2s`. Decryption accepts integer counts 220,000–1,000,000 inclusive and salt inputs 16–64 bytes inclusive, validated before PBKDF2. The full PBKDF2 salt is UTF-8(`PBES2-HS512+A256KW`) || 0x00 || decoded `p2s`. PBKDF2-HMAC-SHA-512 derives a 256-bit AES-KW key to wrap a fresh AES-GCM content key. Password bytes are exact UTF-8, without normalization. Work policy is deliberate: future encryption defaults and backward-decryption policy must be reviewed separately, preserving fixtures.

Limits, checked before key derivation where applicable:

| Input | Limit |
| --- | --- |
| Plaintext or message to sign | 16 MiB |
| Encoded JWE | 24 MiB |
| Decoded protected header | 4 KiB |
| Serialized JWK / protected JWK plaintext | 32 KiB |
| Password | 1–1024 UTF-8 bytes |

JWK imports accept AES-256 (`oct`), RSA 3072/4096 bits with exponent 65537 and full two-prime private parameters, or Ed25519 (`OKP`). RSA integers use canonical unsigned big-endian encodings. Supplied `alg`, `use`, `key_ops`, and `ext` must match the purpose. `key_ops`, if supplied, must exactly match encrypt/decrypt for symmetric keys, encrypt or decrypt for RSA, or sign or verify for Ed25519. Imports are extractable; an explicit `ext: false` is rejected. Ed25519 imports accept compatible `EdDSA` or `Ed25519` algorithm metadata; exports normalize to `EdDSA` and pass only validated material to native import. Public exports have no private fields. Protected JWKs are JSON UTF-8 inside password JWE; no proprietary outer wrapper exists.

Detached Ed25519 signatures follow [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html), exactly 64 raw bytes (`R || S`), or canonical unpadded base64url for text APIs. No JWS header or prehash is added. Text decoding is strict UTF-8, including preserved leading BOM; malformed decrypted UTF-8 fails text decryption while byte decryption remains available.

## Decrypt without this package

This example uses the independent `jose` package (a development test oracle, not a library runtime dependency):

```js
import { compactDecrypt, importJWK } from 'jose';

// Password ciphertext or protected key backup:
const { plaintext, protectedHeader } = await compactDecrypt(
  savedJwe,
  new TextEncoder().encode(password),
  { keyManagementAlgorithms: ['PBES2-HS512+A256KW'], maxPBES2Count: 1000000 },
);
const decoded = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(plaintext);
if (protectedHeader.cty === 'jwk+json') {
  const recoveredJwk = JSON.parse(decoded);
  // Treat a recovered private/symmetric JWK as an unencrypted secret.
}

// For recipient ciphertext, replace the password bytes with:
const privateKey = await importJWK(savedPrivateJwk, 'RSA-OAEP-256');
const recipientPlaintext = await compactDecrypt(recipientJwe, privateKey);

// For direct ciphertext, use the 32 decoded bytes of the symmetric JWK's k.
```

External producers must meet this library's stricter header, key, and work limits. The test suite checks both directions for all three suites and retains fixed test-only ciphertexts. Successful interoperability with this subset does not imply acceptance of every external JWE.
