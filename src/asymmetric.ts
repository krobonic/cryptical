import { EncryptedData } from './internal/jwe.js';
import type { JsonWebKey, WrappableKey, KeyPurpose, KeyForPurpose, EncryptionKeyPair, EncryptionPrivateKey, EncryptionPublicKey, SigningKeyPair, SigningPrivateKey, SigningPublicKey } from './types.js';
import { DecryptionError, EncryptionError, InvalidArgumentError, InvalidKeyError, SignatureError } from './errors.js';
import { bytes, b64, unb64, utf8, text } from './internal/encoding.js';
import { checkKey, cryptoProvider, decryptOperation, native, requireEd25519 } from './internal/crypto.js';
import { contentKey, envelopeArgument, open, parse, seal, sealKey, openKey } from './internal/jwe.js';
import { exportProtectedBytes, importProtectedBytes, exportJwk, exportProtected, importJwk, importProtected } from './internal/keys.js';
export type * from './types.js';
export async function generateEncryptionKeyPair(): Promise<EncryptionKeyPair> {
  return await native(() => cryptoProvider().subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']), new InvalidKeyError('Key generation failed')) as EncryptionKeyPair;
}
export async function generateSigningKeyPair(): Promise<SigningKeyPair> {
  await requireEd25519();
  return await native(() => cryptoProvider().subtle.generateKey('Ed25519', true, ['sign', 'verify']), new InvalidKeyError('Key generation failed')) as SigningKeyPair;
}
export async function encrypt(data: Uint8Array, key: EncryptionPublicKey): Promise<EncryptedData> {
  const copy = bytes(data); checkKey(key, 'encryption', 'wrapKey');
  return recipientSeal(copy, key);
}
async function recipientSeal(data: Uint8Array<ArrayBuffer> | CryptoKey, key: EncryptionPublicKey, cty?: 'jwk+json'): Promise<EncryptedData> {
  return native(async () => {
    const cek = await contentKey([cty ? 'wrapKey' : 'encrypt']);
    const wrapped = new Uint8Array(await cryptoProvider().subtle.wrapKey('raw', cek, key, 'RSA-OAEP'));
    const header = { alg: 'RSA-OAEP-256', enc: 'A256GCM', ...(cty ? { cty } : {}) } as const;
    return cty ? sealKey(data as CryptoKey, cek, header, wrapped) : seal(data as Uint8Array<ArrayBuffer>, cek, header, wrapped);
  }, new EncryptionError('Encryption failed'));
}
export async function decrypt(value: EncryptedData, key: EncryptionPrivateKey): Promise<Uint8Array> {
  envelopeArgument(value); checkKey(key, 'encryption', 'unwrapKey');
  return recipientOpen(value, key);
}
async function recipientOpen(value: EncryptedData, key: EncryptionPrivateKey, cty?: 'jwk+json'): Promise<Uint8Array<ArrayBuffer>> {
  return decryptOperation(async () => {
    const e = parse(value, 'RSA-OAEP-256', cty);
    if (e.encryptedKey.length * 8 !== (key.algorithm as RsaHashedKeyAlgorithm).modulusLength) throw new DecryptionError();
    const cek = await cryptoProvider().subtle.unwrapKey('raw', e.encryptedKey, key, 'RSA-OAEP', 'AES-GCM', false, [cty ? 'unwrapKey' : 'decrypt']);
    if ((cek.algorithm as AesKeyAlgorithm).length !== 256) throw new DecryptionError();
    return cty ? openKey(e, cek) : open(e, cek);
  });
}
/** Protect an extractable symmetric or private key for a recipient. */
export async function wrapKey(key: WrappableKey, recipient: EncryptionPublicKey): Promise<EncryptedData> {
  checkKey(recipient, 'encryption', 'wrapKey');
  if (!key || !key.algorithm) throw new InvalidKeyError('Expected symmetric or private key');
  const purpose = key.algorithm.name === 'AES-GCM' ? 'symmetric' : key.algorithm.name === 'Ed25519' ? 'signing' : 'encryption';
  await exportProtectedBytes(key, purpose); // Validate before native JWK wrapping.
  return recipientSeal(key, recipient, 'jwk+json');
}
/** Restore a wrapped key only if its material matches the explicitly expected purpose. */
export async function unwrapKey<P extends KeyPurpose>(value: EncryptedData, recipient: EncryptionPrivateKey, options: { purpose: P }): Promise<KeyForPurpose<P>> {
  const purpose = options?.purpose;
  if (!['symmetric', 'encryption', 'signing'].includes(purpose)) throw new InvalidArgumentError('Expected key purpose');
  envelopeArgument(value); checkKey(recipient, 'encryption', 'unwrapKey');
  const data = await recipientOpen(value, recipient, 'jwk+json');
  return await importProtectedBytes(data, purpose) as KeyForPurpose<P>;
}
export async function encryptText(value: string, key: EncryptionPublicKey): Promise<EncryptedData> { return encrypt(utf8(value), key); }
export async function decryptText(value: EncryptedData, key: EncryptionPrivateKey): Promise<string> {
  const data = await decrypt(value, key);
  try { return text(data); } catch { throw new DecryptionError(); }
}
export async function sign(data: Uint8Array, key: SigningPrivateKey): Promise<Uint8Array> {
  const copy = bytes(data); checkKey(key, 'signing', 'sign');
  await requireEd25519();
  return new Uint8Array(await native(() => cryptoProvider().subtle.sign('Ed25519', key, copy), new SignatureError('Signing failed')));
}
export async function verify(data: Uint8Array, signature: Uint8Array, key: SigningPublicKey): Promise<boolean> {
  const copy = bytes(data); checkKey(key, 'signing', 'verify');
  if (!(signature instanceof Uint8Array)) throw new InvalidArgumentError('Expected signature bytes');
  if (signature.length !== 64) return false;
  const sig = bytes(signature, 64);
  await requireEd25519();
  return native(() => cryptoProvider().subtle.verify('Ed25519', key, sig, copy), new SignatureError('Verification failed'));
}
export async function signText(value: string, key: SigningPrivateKey): Promise<string> { return b64(await sign(utf8(value), key)); }
export async function verifyText(value: string, signature: string, key: SigningPublicKey): Promise<boolean> {
  const data = utf8(value); checkKey(key, 'signing', 'verify');
  if (typeof signature !== 'string') throw new InvalidArgumentError('Expected signature string');
  let sig: Uint8Array;
  try { sig = unb64(signature, 64); } catch { return false; }
  return verify(data, sig, key);
}
type AsymmetricKey = EncryptionPublicKey | EncryptionPrivateKey | SigningPublicKey | SigningPrivateKey;
export async function exportKey(key: EncryptionPrivateKey | SigningPrivateKey): Promise<JsonWebKey & { d: string }>;
export async function exportKey(key: EncryptionPublicKey | SigningPublicKey): Promise<JsonWebKey & { d?: never }>;
export async function exportKey(key: AsymmetricKey): Promise<JsonWebKey>;
export async function exportKey(key: AsymmetricKey): Promise<JsonWebKey> {
  checkKeyFamily(key);
  return exportJwk(key, key.algorithm.name === 'Ed25519' ? 'signing' : 'encryption');
}
function checkKeyFamily(key: CryptoKey): void {
  if (!key || !key.algorithm) throw new InvalidKeyError('Expected asymmetric key');
  checkKey(key, key.algorithm.name === 'Ed25519' ? 'signing' : 'encryption');
}
export async function importEncryptionKey(jwk: JsonWebKey & { d: string }): Promise<EncryptionPrivateKey>;
export async function importEncryptionKey(jwk: JsonWebKey & { d?: never }): Promise<EncryptionPublicKey>;
export async function importEncryptionKey(jwk: JsonWebKey): Promise<EncryptionPublicKey | EncryptionPrivateKey>;
export async function importEncryptionKey(jwk: JsonWebKey): Promise<EncryptionPublicKey | EncryptionPrivateKey> { return await importJwk(jwk, 'encryption') as EncryptionPublicKey | EncryptionPrivateKey; }
export async function importSigningKey(jwk: JsonWebKey & { d: string }): Promise<SigningPrivateKey>;
export async function importSigningKey(jwk: JsonWebKey & { d?: never }): Promise<SigningPublicKey>;
export async function importSigningKey(jwk: JsonWebKey): Promise<SigningPublicKey | SigningPrivateKey>;
export async function importSigningKey(jwk: JsonWebKey): Promise<SigningPublicKey | SigningPrivateKey> { return await importJwk(jwk, 'signing') as SigningPublicKey | SigningPrivateKey; }
export async function exportKeyWithPassword(key: EncryptionPrivateKey | SigningPrivateKey, password: string): Promise<EncryptedData> {
  checkKeyFamily(key);
  return exportProtected(key, password, key.algorithm.name === 'Ed25519' ? 'signing' : 'encryption');
}
export async function importEncryptionKeyWithPassword(value: EncryptedData, password: string): Promise<EncryptionPrivateKey> { return await importProtected(value, password, 'encryption') as EncryptionPrivateKey; }
export async function importSigningKeyWithPassword(value: EncryptedData, password: string): Promise<SigningPrivateKey> { return await importProtected(value, password, 'signing') as SigningPrivateKey; }

export { EncryptedData } from './internal/jwe.js';
