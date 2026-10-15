import { expect, test, spyOn } from 'bun:test';
import { CompactEncrypt } from 'jose';
import { asymmetric as a, symmetric as s, EncryptedData, InvalidKeyError, DecryptionError, CryptoUnavailableError } from '../index';

for (const modulusLength of [3072, 4096]) test(`RSA ${modulusLength} imports reject unusable material and restore valid keys through every path`, async () => {
  const pair = await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']);
  const jwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  const wrappingKey = await s.generateKey(), recipient = await a.generateEncryptionKeyPair();
  const password = 'test password', challenge = crypto.getRandomValues(new Uint8Array(32));
  const ciphertext = await crypto.subtle.encrypt('RSA-OAEP', pair.publicKey, challenge);
  for (const valid of [true, false]) {
    const supplied = valid ? jwk : { ...jwk, d: 'AQ', p: 'AQ', q: 'AQ', dp: 'AQ', dq: 'AQ', qi: 'AQ' };
    const payload = new TextEncoder().encode(JSON.stringify(supplied));
    const direct = await new CompactEncrypt(payload).setProtectedHeader({ alg: 'dir', enc: 'A256GCM', cty: 'jwk+json' }).encrypt(wrappingKey);
    const rsa = await new CompactEncrypt(payload).setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM', cty: 'jwk+json' }).encrypt(recipient.publicKey);
    const backup = await new CompactEncrypt(payload).setProtectedHeader({ alg: 'PBES2-HS512+A256KW', enc: 'A256GCM', cty: 'jwk+json' }).setKeyManagementParameters({ p2c: 220000 }).encrypt(new TextEncoder().encode(password));
    const restores = [
      () => a.importEncryptionKey(supplied),
      () => a.importEncryptionKeyWithPassword(EncryptedData.fromJWE(backup), password),
      () => s.unwrapKey(EncryptedData.fromJWE(direct), wrappingKey, { purpose: 'encryption' }),
      () => a.unwrapKey(EncryptedData.fromJWE(rsa), recipient.privateKey, { purpose: 'encryption' }),
    ];
    for (const [i, restore] of restores.entries()) {
      if (valid) {
        const key = await restore();
        expect(new Uint8Array(await crypto.subtle.decrypt('RSA-OAEP', key, ciphertext))).toEqual(challenge);
        expect(await a.exportKey(key)).toEqual(jwk);
      } else await expect(restore()).rejects.toBeInstanceOf(i === 0 ? InvalidKeyError : DecryptionError);
    }
  }
}, 30000);

test('RSA usability checks reject incorrect plaintext and preserve unavailable-algorithm errors on all import paths', async () => {
  const pair = await a.generateEncryptionKeyPair(), wrappingKey = await s.generateKey();
  const jwk = await a.exportKey(pair.privateKey), password = 'test password';
  const backup = await a.exportKeyWithPassword(pair.privateKey, password);
  const direct = await s.wrapKey(pair.privateKey, wrappingKey);
  const recipient = await a.wrapKey(pair.privateKey, pair.publicKey);
  const decrypt = crypto.subtle.decrypt.bind(crypto.subtle);
  const spy = spyOn(crypto.subtle, 'decrypt');
  try {
    spy.mockResolvedValue(new Uint8Array(32).buffer);
    await expect(a.importEncryptionKey(jwk)).rejects.toBeInstanceOf(InvalidKeyError);
    spy.mockImplementation((algorithm, key, data) => {
      if (algorithm === 'RSA-OAEP' && key !== pair.privateKey) return Promise.reject(new DOMException('unavailable', 'NotSupportedError'));
      return decrypt(algorithm, key, data);
    });
    for (const restore of [
      () => a.importEncryptionKey(jwk),
      () => a.importEncryptionKeyWithPassword(backup, password),
      () => s.unwrapKey(direct, wrappingKey, { purpose: 'encryption' }),
      () => a.unwrapKey(recipient, pair.privateKey, { purpose: 'encryption' }),
    ]) await expect(restore()).rejects.toBeInstanceOf(CryptoUnavailableError);
  } finally { spy.mockRestore(); }
});
