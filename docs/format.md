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

JWK imports accept AES-256 (`oct`), RSA 3072/4096 bits with exponent 65537 and full two-prime private parameters, or Ed25519 (`OKP`). RSA integers use canonical unsigned big-endian encodings. Supplied `alg`, `use`, `key_ops`, and `ext` must match the purpose. `key_ops`, if supplied, must exactly match encrypt/decrypt for symmetric keys, encrypt or decrypt for RSA, or sign or verify for Ed25519. Imports are extractable; an explicit `ext: false` is rejected. Ed25519 imports accept compatible `EdDSA` or `Ed25519` algorithm metadata; exports normalize to `EdDSA` and pass only validated material to native import. Public exports have no private fields. Protected JWKs are JSON UTF-8 inside password, recipient, or direct symmetric JWE. Recipient wrapping uses `alg: "RSA-OAEP-256"`, `enc: "A256GCM"`, and `cty: "jwk+json"`; the JWK itself is the encrypted payload. Symmetric wrapping uses `alg: "dir"`, `enc: "A256GCM"`, and `cty: "jwk+json"`, with an empty encrypted-key segment. The 32 KiB protected-payload limit applies to every wrapping mechanism. Symmetric and recipient unwrapping require an explicit expected key purpose and rejects public keys. The existing binary version 1 framing supports these envelopes without a format change.

Detached Ed25519 signatures follow [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html), exactly 64 raw bytes (`R || S`), or canonical unpadded base64url for text APIs. No JWS header or prehash is added. Text decoding is strict UTF-8, including preserved leading BOM; malformed decrypted UTF-8 fails text decryption while byte decryption remains available.

## Binary envelope, version 1

Encryption, key wrapping, and protected key exports return `EncryptedData`. `toBinary()` serializes the following custom format; `fromBinary()` parses it. All integers are unsigned, big-endian. Offsets are byte offsets.

| Offset | Length | Field |
| --- | --- | --- |
| 0 | 4 | Magic ASCII `CKIT` (`43 4b 49 54` hex) |
| 4 | 1 | Version, exactly `01` |
| 5 | 4 | H: encoded protected header length |
| 9 | 4 | K: wrapped key length |
| 13 | 4 | C: ciphertext length, excluding tag |
| 17 | H | Exact original base64url protected header, ASCII bytes |
| 17 + H | K | Raw wrapped key (empty for `dir`) |
| 17 + H + K | 12 | Raw IV |
| 29 + H + K | C | Raw ciphertext |
| 29 + H + K + C | 16 | Raw authentication tag |

Total length is `45 + H + K + C` bytes. H is 1–5,462 bytes and must decode to at most 4,096 bytes of valid supported header JSON. K is 0 for `dir`, 40 for PBES2, or 384/512 for RSA. C is at most 16 MiB, or 32 KiB for protected JWKs. Empty plaintext has C=0. The maximum binary length is 16,783,235 bytes. Parsers reject truncation, trailing bytes, invalid lengths, unknown versions, and invalid magic before cryptographic operations. Password work parameters are validated before derivation.

The protected header is intentionally retained in its exact JWE encoding because those ASCII bytes are AES-GCM additional authenticated data. Reformatting JSON or changing duplicate member handling during serialization would invalidate authentication. Binary framing is not additional authenticated data: version 1 accepts one exact layout with no optional or ignored fields. The protected header, IV, ciphertext and tag retain their existing cryptographic authentication semantics; the wrapped key must successfully recover the content key and authenticate the payload. Future versions must assess version-confusion risks rather than silently accepting new framing.

`toJWE()` and `fromJWE()` use the compact serialization described above. Supported JWE → binary → JWE conversions preserve the entire original string exactly, without decrypting or encrypting. The ciphertext remains raw in memory until JWE serialization is requested. Binary parsers snapshot input byte views and serializers return independent arrays.

Both parsers throw `InvalidArgumentError` for the wrong argument type and `DecryptionError` for malformed or unsupported envelopes. Parsing establishes structure only, not authenticity. Decryption also enforces the expected algorithm and payload purpose: ordinary decryption rejects protected key backups, and protected key imports require `cty: "jwk+json"`. Authentication failures return no plaintext.

To decrypt a binary envelope with an independent JWE implementation, first convert it with `EncryptedData.fromBinary(bytes).toJWE()`, or implement this framing specification and reconstruct the five JWE segments. The binary format itself is not JWE or COSE.

## Decrypt JWE without this package

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
