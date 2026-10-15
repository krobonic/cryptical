import { beforeAll, expect, test, spyOn } from 'bun:test';
import { CompactEncrypt, compactDecrypt } from 'jose';
import { symmetric as s, asymmetric as a, EncryptedData, DecryptionError, InvalidArgumentError, InvalidKeyError } from '../index';
import type { SymmetricKey, EncryptionKeyPair, SigningKeyPair } from '../src/types';
import { utf8, text, b64, unb64 } from '../src/internal/encoding';
let kek: SymmetricKey, secret: SymmetricKey, rsa: EncryptionKeyPair, signer: SigningKeyPair;
beforeAll(async () => {
  kek = await s.generateKey(); secret = await s.generateKey();
  rsa = await a.generateEncryptionKeyPair(); signer = await a.generateSigningKeyPair();
});

test('symmetric wrapping restores all key types from binary and JWE', async () => {
  for (const [key, purpose] of [[secret, 'symmetric'], [rsa.privateKey, 'encryption'], [signer.privateKey, 'signing']] as const) {
    const wrapped = await s.wrapKey(key, kek);
    expect(wrapped.toJWE().split('.')[1]).toBe('');
    expect(JSON.parse(text(unb64(wrapped.toJWE().split('.')[0]!, 4096)))).toEqual({ alg: 'dir', enc: 'A256GCM', cty: 'jwk+json' });
    expect((await s.wrapKey(key, kek)).toJWE()).not.toBe(wrapped.toJWE());
    for (const parsed of [EncryptedData.fromBinary(wrapped.toBinary()), EncryptedData.fromJWE(wrapped.toJWE())]) {
      const restored = await s.unwrapKey(parsed, kek, { purpose });
      expect(await crypto.subtle.exportKey('jwk', restored)).toEqual(await crypto.subtle.exportKey('jwk', key));
      for (const wrong of ['symmetric', 'encryption', 'signing'] as const) if (wrong !== purpose) {
        await expect(s.unwrapKey(parsed, kek, { purpose: wrong })).rejects.toBeInstanceOf(DecryptionError);
      }
    }
  }
  const restored = await s.unwrapKey(await s.wrapKey(secret, kek), kek, { purpose: 'symmetric' });
  expect(await s.decryptText(await s.encryptText('test', secret), restored)).toBe('test');
  const privateKey = await s.unwrapKey(await s.wrapKey(rsa.privateKey, kek), kek, { purpose: 'encryption' });
  expect(await a.decryptText(await a.encryptText('test', rsa.publicKey), privateKey)).toBe('test');
  const signingKey = await s.unwrapKey(await s.wrapKey(signer.privateKey, kek), kek, { purpose: 'signing' });
  expect(await a.verifyText('test', await a.signText('test', signingKey), signer.publicKey)).toBe(true);
});

test('validates payloads, wrapping key usages and options; allows nonextractable wrapping keys', async () => {
  const hidden = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['wrapKey', 'unwrapKey']) as SymmetricKey;
  const wrapped = await s.wrapKey(secret, hidden);
  expect(await s.exportKey(await s.unwrapKey(wrapped, hidden, { purpose: 'symmetric' }))).toEqual(await s.exportKey(secret));
  for (const key of [hidden, rsa.publicKey, signer.publicKey, null, {}]) await expect(s.wrapKey(key as never, kek)).rejects.toBeInstanceOf(InvalidKeyError);
  const small = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 128 }, true, ['encrypt', 'decrypt']);
  const encryptOnly = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const decryptOnly = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['decrypt']);
  for (const key of [small, rsa.publicKey, decryptOnly]) await expect(s.wrapKey(secret, key as never)).rejects.toBeInstanceOf(InvalidKeyError);
  for (const key of [small, rsa.privateKey, encryptOnly]) await expect(s.unwrapKey(wrapped, key as never, { purpose: 'symmetric' })).rejects.toBeInstanceOf(InvalidKeyError);
  for (const options of [null, undefined, {}, { purpose: 'invalid' }]) await expect(s.unwrapKey(wrapped, hidden, options as never)).rejects.toBeInstanceOf(InvalidArgumentError);
  const options: { purpose: 'symmetric' | 'signing' } = { purpose: 'symmetric' };
  const pending = s.unwrapKey(wrapped, hidden, options); options.purpose = 'signing';
  expect((await pending).type).toBe('secret');
});

for (const usages of [['encrypt', 'decrypt'], ['encrypt'], ['decrypt'], ['encrypt', 'decrypt', 'wrapKey']] as KeyUsage[][]) {
  test(`export paths reject symmetric payload usages ${usages.join(', ')}`, async () => {
    const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, usages) as SymmetricKey;
    const jwk = await crypto.subtle.exportKey('jwk', key);
    await expect(s.importKey(jwk)).rejects.toBeInstanceOf(InvalidKeyError);
    await expect(s.exportKey(key)).rejects.toBeInstanceOf(InvalidKeyError);
    await expect(s.exportKeyWithPassword(key, 'password')).rejects.toBeInstanceOf(InvalidKeyError);
    await expect(s.wrapKey(key, kek)).rejects.toBeInstanceOf(InvalidKeyError);
    await expect(a.wrapKey(key, rsa.publicKey)).rejects.toBeInstanceOf(InvalidKeyError);
    expect(key.usages).toEqual(usages);
  });
}

test('restricted nonextractable wrapping keys can wrap and unwrap valid payloads', async () => {
  const raw = await crypto.subtle.exportKey('raw', kek);
  const encryptOnly = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['wrapKey']) as SymmetricKey;
  const decryptOnly = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['unwrapKey']) as SymmetricKey;
  const wrapped = await s.wrapKey(secret, encryptOnly);
  const restored = await s.unwrapKey(wrapped, decryptOnly, { purpose: 'symmetric' });
  expect(await s.exportKey(restored)).toEqual(await s.exportKey(secret));
  expect(await s.decryptText(await s.encryptText('restored', secret), restored)).toBe('restored');
});

test('rejects wrong keys, tampering, ordinary data and other wrapping mechanisms', async () => {
  const wrapped = await s.wrapKey(secret, kek);
  await expect(s.unwrapKey(wrapped, secret, { purpose: 'symmetric' })).rejects.toBeInstanceOf(DecryptionError);
  await expect(s.decrypt(wrapped, kek)).rejects.toBeInstanceOf(DecryptionError);
  for (const value of [await s.encryptText(JSON.stringify(await s.exportKey(secret)), kek), await a.wrapKey(secret, rsa.publicKey), await s.exportKeyWithPassword(secret, 'password')]) {
    await expect(s.unwrapKey(value, kek, { purpose: 'symmetric' })).rejects.toBeInstanceOf(DecryptionError);
  }
  await expect(a.unwrapKey(wrapped, rsa.privateKey, { purpose: 'symmetric' })).rejects.toBeInstanceOf(DecryptionError);
  await expect(s.importKeyWithPassword(wrapped, 'password')).rejects.toBeInstanceOf(DecryptionError);
  for (const index of [2, 3, 4]) {
    const parts = wrapped.toJWE().split('.'); parts[index] = (parts[index]![0] === 'A' ? 'B' : 'A') + parts[index]!.slice(1);
    await expect(s.unwrapKey(EncryptedData.fromJWE(parts.join('.')), kek, { purpose: 'symmetric' })).rejects.toBeInstanceOf(DecryptionError);
  }
  const parts = wrapped.toJWE().split('.'); parts[0] = b64(utf8(JSON.stringify({ alg: 'dir', enc: 'A256GCM' })));
  await expect(s.decrypt(EncryptedData.fromJWE(parts.join('.')), kek)).rejects.toBeInstanceOf(DecryptionError);
});

test('independent JOSE interoperates and invalid protected JWKs are rejected', async () => {
  const raw = unb64((await s.exportKey(kek)).k!, 32), jwk = await s.exportKey(secret);
  const decoded = await compactDecrypt((await s.wrapKey(secret, kek)).toJWE(), raw);
  expect(decoded.protectedHeader.cty).toBe('jwk+json');
  expect(JSON.parse(text(decoded.plaintext))).toEqual(jwk);
  const produce = (payload: Uint8Array) => new CompactEncrypt(payload).setProtectedHeader({ alg: 'dir', enc: 'A256GCM', cty: 'jwk+json' }).encrypt(raw);
  const valid = EncryptedData.fromJWE(await produce(utf8(JSON.stringify(jwk))));
  expect(await s.exportKey(await s.unwrapKey(valid, kek, { purpose: 'symmetric' }))).toEqual(jwk);
  for (const payload of [utf8('null'), utf8('bad json'), new Uint8Array([255]), utf8(JSON.stringify({ ...jwk, k: 'AA' })), utf8(JSON.stringify({ ...jwk, key_ops: ['sign'] }))]) {
    await expect(s.unwrapKey(EncryptedData.fromJWE(await produce(payload)), kek, { purpose: 'symmetric' })).rejects.toBeInstanceOf(DecryptionError);
  }
  const publicPayload = EncryptedData.fromJWE(await produce(utf8(JSON.stringify(await a.exportKey(rsa.publicKey)))));
  await expect(s.unwrapKey(publicPayload, kek, { purpose: 'encryption' })).rejects.toBeInstanceOf(DecryptionError);
  const oversized = await produce(new Uint8Array(32769));
  const unwrap = spyOn(crypto.subtle, 'unwrapKey');
  try {
    expect(() => EncryptedData.fromJWE(oversized)).toThrow(DecryptionError);
    expect(unwrap).not.toHaveBeenCalled();
  } finally { unwrap.mockRestore(); }
});
