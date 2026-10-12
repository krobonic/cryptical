import { expect, test, spyOn } from 'bun:test';
import { EncryptedData, symmetric as s, asymmetric as a, DecryptionError, InvalidArgumentError, InvalidKeyError, CryptoUnavailableError } from '../index';
import { b64, utf8, unb64, text, MAX_BYTES } from '../src/internal/encoding';
import type { SymmetricKey, EncryptionPublicKey, SigningPrivateKey } from '../src/types';
async function parsed<T>(value: string, operation: (data: EncryptedData) => Promise<T>): Promise<T> { return operation(EncryptedData.fromJWE(value)); }
function header(value: string | EncryptedData, change: Record<string, unknown>): string {
  const p = (typeof value === 'string' ? value : value.toJWE()).split('.'); p[0] = b64(utf8(JSON.stringify({ ...JSON.parse(text(unb64(p[0]!, 4096))), ...change }))); return p.join('.');
}
test('wrong keys, all segments, unsupported and malformed envelopes fail uniformly', async () => {
  const key = await s.generateKey(), other = await s.generateKey(), sealed = await s.encryptText('secret', key);
  await expect(s.decryptText(sealed, other)).rejects.toBeInstanceOf(DecryptionError);
  for (let i = 0; i < 5; i++) {
    const parts = sealed.toJWE().split('.'); parts[i] = parts[i] ? (parts[i]![0] === 'A' ? 'B' : 'A') + parts[i]!.slice(1) : 'AA';
    await expect(parsed(parts.join('.'), data => s.decrypt(data, key))).rejects.toBeInstanceOf(DecryptionError);
  }
  for (const value of ['', '....', sealed.toJWE() + '=', header(sealed, { alg: 'none' }), header(sealed, { zip: 'DEF' }), header(sealed, { crit: [] }), header(sealed, { jwk: {} }), 'a'.repeat(24 * 1024 * 1024 + 1)]) await expect(parsed(value, data => s.decrypt(data, key))).rejects.toBeInstanceOf(DecryptionError);
  await expect(s.decryptText(await s.encrypt(new Uint8Array([255]), key), key)).rejects.toBeInstanceOf(DecryptionError);
});
test('password policy is validated before derivation', async () => {
  const sealed = await s.encryptTextWithPassword('secret', 'password');
  await expect(s.decryptWithPassword(sealed, 'wrong')).rejects.toBeInstanceOf(DecryptionError);
  const derive = spyOn(crypto.subtle, 'deriveKey');
  try {
    for (const p2c of [0, 219999, 1000001, 220000.5, null, '220000', 1e100]) await expect(parsed(header(sealed, { p2c }), data => s.decryptWithPassword(data, 'password'))).rejects.toBeInstanceOf(DecryptionError);
    for (const p2s of ['', b64(new Uint8Array(15)), b64(new Uint8Array(65)), 'AA==']) await expect(parsed(header(sealed, { p2s }), data => s.decryptWithPassword(data, 'password'))).rejects.toBeInstanceOf(DecryptionError);
    expect(derive).not.toHaveBeenCalled();
  } finally { derive.mockRestore(); }
  for (const password of ['', 'a'.repeat(1025), '💡'.repeat(257), '\ud800']) await expect(s.encryptTextWithPassword('', password)).rejects.toBeInstanceOf(InvalidArgumentError);
  await expect(s.importKeyWithPassword(sealed, 'password')).rejects.toBeInstanceOf(DecryptionError);
});
test('size, argument, key material and metadata validation', async () => {
  const key = await s.generateKey();
  await expect(s.encrypt(new Uint8Array(MAX_BYTES + 1), key)).rejects.toBeInstanceOf(InvalidArgumentError);
  await expect(s.encryptText(42 as never, key)).rejects.toBeInstanceOf(InvalidArgumentError);
  await expect(s.decrypt(42 as never, key)).rejects.toBeInstanceOf(InvalidArgumentError);
  const jwk = await s.exportKey(key);
  for (const change of [{ k: 'AA' }, { k: jwk.k + '=' }, { alg: 'A128GCM' }, { use: 'sig' }, { ext: false }, { key_ops: ['encrypt'] }, { d: 'AA' }]) await expect(s.importKey({ ...jwk, ...change })).rejects.toBeInstanceOf(InvalidKeyError);
  const large = new Uint8Array(MAX_BYTES); large[large.length - 1] = 255;
  expect(await s.decrypt(await s.encrypt(large, key), key)).toEqual(large);
}, 30000);
test('wrong recipients, signers and key purposes', async () => {
  const rsa = await a.generateEncryptionKeyPair(), other = await a.generateEncryptionKeyPair(), ed = await a.generateSigningKeyPair(), otherEd = await a.generateSigningKeyPair();
  await expect(a.decrypt(await a.encryptText('secret', rsa.publicKey), other.privateKey)).rejects.toBeInstanceOf(DecryptionError);
  await expect(s.encryptText('', ed.privateKey as unknown as SymmetricKey)).rejects.toBeInstanceOf(InvalidKeyError);
  await expect(a.encryptText('', ed.publicKey as unknown as EncryptionPublicKey)).rejects.toBeInstanceOf(InvalidKeyError);
  await expect(a.signText('', rsa.privateKey as unknown as SigningPrivateKey)).rejects.toBeInstanceOf(InvalidKeyError);
  const signature = await a.signText('test', ed.privateKey);
  expect(await a.verifyText('test', signature, otherEd.publicKey)).toBe(false);
  for (const sig of ['', signature + '=', signature.slice(0, -1) + '!', 'A'.repeat(86), 'A'.repeat(100000)]) expect(await a.verifyText('test', sig, ed.publicKey)).toBe(false);
  await expect(a.verifyText('', 1 as never, ed.publicKey)).rejects.toBeInstanceOf(InvalidArgumentError);
  await expect(a.exportKeyWithPassword(rsa.publicKey as never, 'password')).rejects.toBeInstanceOf(InvalidKeyError);
}, 30000);
test('missing native crypto has an explicit typed error', async () => {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto')!;
  try {
    Object.defineProperty(globalThis, 'crypto', { configurable: true, value: undefined });
    await expect(s.generateKey()).rejects.toBeInstanceOf(CryptoUnavailableError);
  } finally { Object.defineProperty(globalThis, 'crypto', descriptor); }
});
test('original header bytes and last duplicate member are authenticated', async () => {
  const key = await s.generateKey();
  const protectedHeader = b64(utf8('{ "alg":"ignored", "enc":"A256GCM", "alg":"dir" }'));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: utf8(protectedHeader), tagLength: 128 }, key, utf8('original header')));
  const value = [protectedHeader, '', b64(iv), b64(encrypted.subarray(0, -16)), b64(encrypted.subarray(-16))].join('.');
  expect(await s.decryptText(EncryptedData.fromBinary(EncryptedData.fromJWE(value).toBinary()), key)).toBe('original header');
  await expect(parsed(header(value, {}), data => s.decryptText(data, key))).rejects.toBeInstanceOf(DecryptionError);
  const parts = value.split('.'), tag = parts[4]!;
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  parts[4] = tag.slice(0, -1) + alphabet[alphabet.indexOf(tag.at(-1)!) + 1];
  await expect(parsed(parts.join('.'), data => s.decrypt(data, key))).rejects.toBeInstanceOf(DecryptionError);
});
test('protected JWK size, headers and oversized salts are rejected before KDF', async () => {
  const key = await s.generateKey(), backup = await s.exportKeyWithPassword(key, 'password');
  const derive = spyOn(crypto.subtle, 'deriveKey');
  try {
    const oversized = backup.toJWE().split('.'); oversized[3] = b64(new Uint8Array(32769));
    await expect(parsed(oversized.join('.'), data => s.importKeyWithPassword(data, 'password'))).rejects.toBeInstanceOf(DecryptionError);
    await expect(parsed(header(backup, { cty: 'application/json' }), data => s.importKeyWithPassword(data, 'password'))).rejects.toBeInstanceOf(DecryptionError);
    await expect(parsed(header(backup, { p2s: 'A'.repeat(100000) }), data => s.importKeyWithPassword(data, 'password'))).rejects.toBeInstanceOf(DecryptionError);
    expect(derive).not.toHaveBeenCalled();
  } finally { derive.mockRestore(); }
  await expect(s.importKey({ kty: 'oct', k: 'A'.repeat(32769) })).rejects.toBeInstanceOf(InvalidKeyError);
});
test('asynchronous password/encryption/signing operations snapshot views', async () => {
  const rsa = await a.generateEncryptionKeyPair(), ed = await a.generateSigningKeyPair();
  const data = new Uint8Array([9, 1, 2, 3, 9]), view = data.subarray(1, 4), expected = new Uint8Array(view);
  const encrypted = a.encrypt(view, rsa.publicKey), password = s.encryptWithPassword(view, 'password'), signature = a.sign(view, ed.privateKey);
  data.fill(0);
  expect(await a.decrypt(await encrypted, rsa.privateKey)).toEqual(expected);
  expect(await s.decryptWithPassword(await password, 'password')).toEqual(expected);
  expect(await a.verify(expected, await signature, ed.publicKey)).toBe(true);
});
test('a native provider failing Ed25519 vectors is explicitly unavailable', async () => {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto')!;
  const original = crypto;
  try {
    Object.defineProperty(globalThis, 'crypto', { configurable: true, value: {
      getRandomValues: original.getRandomValues.bind(original),
      subtle: { importKey: original.subtle.importKey.bind(original.subtle), verify: async () => false },
    } });
    await expect(a.generateSigningKeyPair()).rejects.toBeInstanceOf(CryptoUnavailableError);
  } finally { Object.defineProperty(globalThis, 'crypto', descriptor); }
});
