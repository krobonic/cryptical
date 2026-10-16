declare const purpose: unique symbol;
export type SymmetricKey = CryptoKey & { readonly type: 'secret'; readonly [purpose]: 'symmetric' };
export type EncryptionPublicKey = CryptoKey & { readonly type: 'public'; readonly [purpose]: 'encryption-public' };
export type EncryptionPrivateKey = CryptoKey & { readonly type: 'private'; readonly [purpose]: 'encryption-private' };
export type SigningPublicKey = CryptoKey & { readonly type: 'public'; readonly [purpose]: 'signing-public' };
export type SigningPrivateKey = CryptoKey & { readonly type: 'private'; readonly [purpose]: 'signing-private' };
export interface EncryptionKeyPair { publicKey: EncryptionPublicKey; privateKey: EncryptionPrivateKey }
export interface SigningKeyPair { publicKey: SigningPublicKey; privateKey: SigningPrivateKey }

/** Key material supported by symmetric and recipient wrapping. Public keys use ordinary JWK export. */
export type WrappableKey = SymmetricKey | EncryptionPrivateKey | SigningPrivateKey;
export type KeyPurpose = 'symmetric' | 'encryption' | 'signing';
export type KeyForPurpose<P extends KeyPurpose> = P extends 'symmetric' ? SymmetricKey : P extends 'encryption' ? EncryptionPrivateKey : SigningPrivateKey;

/** Portable JSON Web Key shape, also available to consumers without DOM types. */
export interface JsonWebKey {
  alg?: string;
  crv?: string;
  d?: string;
  dp?: string;
  dq?: string;
  e?: string;
  ext?: boolean;
  k?: string;
  key_ops?: string[];
  kty?: string;
  n?: string;
  oth?: { d?: string; r?: string; t?: string }[];
  p?: string;
  q?: string;
  qi?: string;
  use?: string;
  x?: string;
  y?: string;
}
