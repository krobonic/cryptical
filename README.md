# CypherKit

A lightweight, TypeScript-first cryptography library built on top of the Web Crypto API. This library provides high-level abstractions for common cryptographic operations including symmetric encryption, asymmetric encryption, and key management.

> [!WARNING]
> Very early development. The API is highly unstable and may change at any time. Features may be added or dropped at any time.

## Features

- **Symmetric Encryption**: Easy-to-use AES-GCM encryption via `DataKey`.
- **Key Wrapping**: Securely wrap and unwrap keys using AES-KW via `WrappingKey`.
- **Password-Based Key Derivation**: Derive secure keys from passwords using PBKDF2 via `PasswordKey`.
- **Asymmetric Encryption**: RSA-OAEP encryption and decryption via `KeyPair`.
- **Type Safety**: Built with TypeScript for full type support and safety.

## Installation

```bash
npm install cypherkit
```

## Usage

### Symmetric Encryption

Use `DataKey` for standard AES-GCM encryption and decryption.

```typescript
import { Symmetric, Text } from 'cipherkit';

// Generate a new 256-bit AES-GCM key
const dataKey = await Symmetric.DataKey.generate();

// Encrypt data
const secretMessage = "Hello, World!";
const encrypted = await dataKey.encrypt(Text.encode(secretMessage));

// Decrypt data
const decryptedBytes = await dataKey.decrypt(encrypted);
const decryptedMessage = Text.decode(decryptedBytes);

console.log(decryptedMessage); // "Hello, World!"
```

### Password-Based Key Derivation

Derive a `DataKey` or `WrappingKey` from a user-provided password using PBKDF2.

```typescript
import { Symmetric } from 'cipherkit';

const password = "my-secure-password";
const passwordKey = await Symmetric.PasswordKey.import(password);

// Derive a DataKey with a random salt
const { salt, dataKey } = await passwordKey.deriveDataKey();

// You can later re-derive the same key using the same salt
const derivedAgain = await passwordKey.deriveDataKey(salt);
```

### Key Wrapping

Securely wrap keys for storage or transmission using `WrappingKey` (AES-KW).

```typescript
import { Symmetric } from 'cipherkit';

const wrappingKey = await Symmetric.WrappingKey.generate();
const dataKey = await Symmetric.DataKey.generate();

// Wrap the DataKey
const wrappedKeyBytes = await wrappingKey.wrapKey(dataKey);

// Unwrap back to a DataKey
const unwrappedDataKey = await wrappingKey.unwrapDataKey(wrappedKeyBytes);
```

### Asymmetric Encryption

Use `KeyPair` for RSA-OAEP asymmetric encryption.

```typescript
import { Asymmetric, Text } from 'cipherkit';

// Generate a 4096-bit RSA-OAEP key pair
const keyPair = await Asymmetric.KeyPair.generate();

// Encrypt with the public key
const secret = Text.encode("Top secret content");
const encrypted = await keyPair.encrypt(secret);

// Decrypt with the private key
const decrypted = await keyPair.decrypt(encrypted);
console.log(Text.decode(decrypted)); // "Top secret content"
```

### Text Utilities

The `Text` class provides simple wrappers for `TextEncoder` and `TextDecoder`.

```typescript
import { Text } from 'cipherkit';

const bytes = Text.encode("Hello");
const str = Text.decode(bytes);
```

## API Overview

### Symmetric
- `DataKey`: AES-GCM encryption/decryption.
- `PasswordKey`: PBKDF2 key derivation from passwords.
- `WrappingKey`: AES-KW key wrapping.
- `EncryptedData`: Data structure for IV and ciphertext.

### Asymmetric
- `KeyPair`: RSA-OAEP key pair generation, encryption, and decryption.

### Utilities
- `Text`: Helper for string to/from Uint8Array conversion.
- `Random`: Cryptographically strong random value generation.
- `Helpers`: Internal conversion utilities.
