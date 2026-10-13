# Security and release status

This is pre-release software with **no independent security review**. An external review of the implementation, formats, error handling, and adversarial tests is a production-release gate. Passing tests establishes functionality and catches known failure classes; it is not an audit claim.

## Responsibilities and threat model

Authenticated encryption protects confidentiality and detects modification when keys remain secret. Anyone with a recipient's public key can encrypt to them; recipient encryption does not authenticate a sender. Verify signing-key identity through a trusted application mechanism before relying on signatures. This library provides no identity directory, message transport, sessions, replay protection, multi-recipient protocol, forward secrecy, or combined sign-and-encrypt protocol. Password encryption is not a login password-hashing API.

An attacker with a password ciphertext can guess passwords offline. Use randomly generated high-entropy passphrases; length limits do not measure entropy. The initial 220,000 PBKDF2-HMAC-SHA-512 iteration baseline follows [OWASP password storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html), using the native-only algorithms required by this project. It is not a guarantee against weak passwords or a uniform device-latency promise. Password parameters are bounded before derivation to reduce resource abuse. Applications must still limit request rates, concurrency, and total data volume.

Generated/imported long-lived keys are extractable for portability. Unprotected JWK exports can expose private/symmetric secrets. Store and transmit them deliberately; prefer protected backups for storage and use separate strong passwords where appropriate. Working PBKDF2 and wrapping keys are nonextractable. Content keys are extractable only where wrapping/export requires it. No passwords or derived keys are cached. Compromised JavaScript/XSS can read plaintext and invoke or export usable keys. Native CryptoKey objects do not defeat compromised application code, and JavaScript cannot guarantee memory erasure. There is no recovery without keys/passwords.

All encryption uses native random IVs. Rotate long-lived direct symmetric keys before 2^24 encryptions, counting all devices/processes sharing the key. This conservative bound is guidance; the stateless library cannot enforce a global counter. Password/recipient messages have fresh content keys. Never choose IVs yourself. RSA-3072 does not provide 256-bit security merely because its content cipher is AES-256.

Only bounded one-shot operations are supported. Payloads are copied; explicit JWE serialization adds base64 allocation. Binary envelopes retain raw ciphertext. Parsing validates structure and resource bounds but does not authenticate the payload; authentication occurs during decryption. No plaintext is returned until authentication succeeds. Decryption errors do not reveal which processing stage failed, but constant timing is not promised. Protect applications against timing-based oracles independently.

## Local verification record

Implementation run on Mac17,8 / Apple M5 Pro, macOS 26.5.2 (25F84), 2026-09-24:

- Frozen-lockfile install, portable and consumer type checks, build, package checks and 17 core/security/interoperability tests passed. Combined minified/gzipped browser entry: 4,427 bytes (15,360-byte budget).
- Bun 1.4.2, Node 22.14.0, Playwright 1.63.0 Chromium 153.0.8010.12, Firefox 155.0 and WebKit 26.6 passed all **25 encryption/JWK/encrypted-backup producer/consumer combinations**.
- Bun, Node, Chromium and Firefox passed all **16 full API combinations**, including signatures and protected signing keys.
- **Full runtime suite remains failing:** macOS Playwright WebKit 26.6 fails RFC 8032 TEST 1 (valid empty-message signature). WebKit 26.0 also failed, including an isolated native sign/verify round-trip with no library involved. Nonempty native round-trips passed in that probe. Signing APIs reject affected providers with CryptoUnavailableError after a cached native vector check. No fallback or altered message encoding is used. These WebKit builds are not supported for signing; this is a release blocker for the full proposed browser matrix, not a passing Safari claim.
- Actual Node 24.21.0 and 26.10.0 additionally passed built-package exports, fixed vectors/fixtures, full API round-trips and bidirectional exchanges with Bun. The complete browser matrix for each Node line remains a CI gate.
- Node 22.14.0 password operations on this desktop, one warm-up followed by 10 samples: encryption median **46.77 ms**, max **51.39 ms**; decryption median **46.70 ms**, max **52.04 ms**. These are local measurements, not performance guarantees. Mobile timings remain unmeasured.

Actual Chrome/Edge, Safari/iOS Safari, mobile benchmarks, and independent review are still outstanding. Engine-specific behavior can differ by OS/native provider; CI intentionally keeps the full-support gate strict.

## Binary envelope verification, 2026-10-12

- Core, security, interoperability and serialization coverage: 25 passing tests, including independent golden binary bytes, exact JWE preservation, malformed framing, authentication failures, defensive copies and protected key backups. The ordinary suite skips the separate runtime gate.
- Portable source, test and declaration-consumer TypeScript checks passed; build and package checks passed. Combined minified/gzipped browser entry: 4,993 bytes (15,360-byte budget). The local `tsc` launcher was broken (`../lib/tsc.js` could not be resolved), so checks invoked the installed TypeScript compiler directly with Bun.
- Bun 1.4.2, Node 22.14.0, Chromium 153.0.8010.12 and WebKit 26.6 passed all 16 available encryption/JWK/protected-backup producer/consumer combinations, exercising both binary and JWE serialization. Bun, Node and Chromium passed all nine available full API combinations.
- The full runtime gate still fails: Firefox could not launch because its generated profile directory was inaccessible, including a retry with a different temporary directory. WebKit 26.6 still fails the previously recorded native Ed25519 vector. The harness now continues after a browser launch failure to collect results from other engines, then fails the full-support gate.

## Recipient key wrapping verification, 2026-10-12

- 30 core/security/interoperability/serialization tests passed, including all three wrapped key purposes, binary/JWE round trips, independent JOSE interchange, wrong-purpose and public-key rejection, nonextractable keys, tampering, payload separation, and malformed decrypted JWKs.
- Source, test and declaration-consumer checks, build and package checks passed. Combined browser entry: 5,136 bytes minified/gzipped. The installed TypeScript compiler was invoked directly with Bun because of the previously recorded launcher issue.
- The runtime harness now exchanges wrapped symmetric and RSA private keys in both serializations across all 16 available Bun/Node/Chromium/WebKit combinations. All nine Bun/Node/Chromium full API combinations also passed, including wrapped Ed25519 private keys.
- The full runtime gate remains failing for the previously recorded Firefox profile launch error and WebKit native Ed25519 failure. Recipient wrapping does not authenticate the sender; restored keys remain extractable under the existing import policy.

## Symmetric key wrapping verification, 2026-10-12

- All 34 core/security/interoperability/serialization tests passed. New coverage includes symmetric wrapping of all three supported key purposes, binary/JWE serialization, JOSE interchange, nonextractable wrapping keys, key usage validation, purpose validation, tampering, and rejection of incompatible envelopes and invalid JWKs.
- Source, test and consumer declaration checks, build and package checks passed using the installed TypeScript compiler directly. Combined browser entry: 5,172 bytes minified/gzipped.
- Symmetrically wrapped AES and RSA keys passed all 16 available Bun/Node/Chromium/WebKit producer/consumer combinations. Wrapped Ed25519 keys also passed the nine Bun/Node/Chromium full API combinations. The full runtime gate still fails on the existing Firefox profile launch error and WebKit Ed25519 vector failure.
- Symmetric wrapping uses fresh random AES-GCM IVs under the wrapping key. Count these operations together with ordinary encryption when applying the direct-key rotation guidance above. A wrapping key may be nonextractable; the payload key must be extractable.

## Runtime and release gates

Target Node 22.13+ on supported release lines; CI runs Node 22, 24, and 26 (26 is additionally a smoke target). Browsers require HTTPS or localhost and native AES-GCM, AES-KW, PBKDF2/SHA-512, RSA-OAEP/SHA-256 and Ed25519. Unsupported native algorithms raise CryptoUnavailableError; no polyfill, WASM, algorithm substitution, network discovery, or handwritten cryptography is used.

The automated runtime harness tests built JavaScript in Bun, actual Node and Playwright Chromium/Firefox/WebKit. It requires all 25 producer/consumer combinations for ciphertexts, signatures, JWKs and protected backups; the local partial results and failing gate are recorded above. It also runs fixed earlier fixtures and invalid-signature vectors in every engine. Playwright WebKit is not shipped Safari; automated engines are not evidence of actual Safari/iOS Safari or Chrome/Edge release testing.

Before production release, record all of the following:

- CI success for each Node matrix entry and all browser engines.
- Current Chrome and Edge versions, actual macOS Safari and actual iOS Safari versions/device names; use the same harness over HTTPS, and exchange a note and protected key backup with Node in both directions.
- On named desktop and mobile devices, warm up once, then run 10 password encryptions/decryptions and record median/max milliseconds. The harness exposes `benchmark()` and a button for this purpose.
- 16 MiB success, over-limit rejection, no plaintext on authentication failure, and decryption of an earlier fixture.
- Independent security-review report and resolution of findings.

The browser harness is `tests/runtime/index.html`; runtime setup generates its companion module. Run `bun run test:runtime` first, then serve the repository locally for testing or host a development copy over HTTPS. Test artifacts contain public test-only secrets and must never be reused for production.

Manual devices and external review cannot be simulated by the automated test suite. Until release records identify those results, browser support remains conditional.
