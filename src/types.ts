declare const purpose: unique symbol;
export type SymmetricKey = CryptoKey & { readonly type: 'secret'; readonly [purpose]: 'symmetric' };
export type EncryptionPublicKey = CryptoKey & { readonly type: 'public'; readonly [purpose]: 'encryption-public' };
export type EncryptionPrivateKey = CryptoKey & { readonly type: 'private'; readonly [purpose]: 'encryption-private' };
export type SigningPublicKey = CryptoKey & { readonly type: 'public'; readonly [purpose]: 'signing-public' };
export type SigningPrivateKey = CryptoKey & { readonly type: 'private'; readonly [purpose]: 'signing-private' };
export interface EncryptionKeyPair { publicKey: EncryptionPublicKey; privateKey: EncryptionPrivateKey }
export interface SigningKeyPair { publicKey: SigningPublicKey; privateKey: SigningPrivateKey }
