import { beforeAll, expect, test, spyOn } from 'bun:test';
import { CompactEncrypt, compactDecrypt, importJWK } from 'jose';
import { asymmetric as a, symmetric as s, EncryptedData, DecryptionError, InvalidArgumentError, InvalidKeyError } from '../index';
import type { EncryptionKeyPair, SigningKeyPair, SymmetricKey } from '../src/types';
import { b64, text, utf8, unb64 } from '../src/internal/encoding';
let recipient: EncryptionKeyPair, other: EncryptionKeyPair, signer: SigningKeyPair, secret: SymmetricKey;
beforeAll(async () => {
  recipient = await a.generateEncryptionKeyPair(); other = await a.generateEncryptionKeyPair();
  signer = await a.generateSigningKeyPair(); secret = await s.generateKey();
});

test('wraps all supported key types in binary and JWE with usable typed results', async () => {
  const cases = [
    { key: secret, purpose: 'symmetric' },
    { key: other.privateKey, purpose: 'encryption' },
    { key: signer.privateKey, purpose: 'signing' },
  ] as const;
  for (const { key, purpose } of cases) {
    const wrapped = await a.wrapKey(key, recipient.publicKey);
    expect(JSON.parse(text(unb64(wrapped.toJWE().split('.')[0]!, 4096)))).toEqual({ alg: 'RSA-OAEP-256', enc: 'A256GCM', cty: 'jwk+json' });
    for (const data of [EncryptedData.fromJWE(wrapped.toJWE()), EncryptedData.fromBinary(wrapped.toBinary())]) {
      const restored = await a.unwrapKey(data, recipient.privateKey, { purpose });
      expect(restored.extractable).toBe(true);
      expect(await crypto.subtle.exportKey('jwk', restored)).toEqual(await crypto.subtle.exportKey('jwk', key));
      for (const wrong of ['symmetric', 'encryption', 'signing'] as const) {
        if (wrong !== purpose) await expect(a.unwrapKey(data, recipient.privateKey, { purpose: wrong })).rejects.toBeInstanceOf(DecryptionError);
      }
    }
  }
  const symmetric = await a.unwrapKey(await a.wrapKey(secret, recipient.publicKey), recipient.privateKey, { purpose: 'symmetric' });
  expect(await s.decryptText(await s.encryptText('message', secret), symmetric)).toBe('message');
  const encryption = await a.unwrapKey(await a.wrapKey(other.privateKey, recipient.publicKey), recipient.privateKey, { purpose: 'encryption' });
  expect(await a.decryptText(await a.encryptText('message', other.publicKey), encryption)).toBe('message');
  const signing = await a.unwrapKey(await a.wrapKey(signer.privateKey, recipient.publicKey), recipient.privateKey, { purpose: 'signing' });
  expect(await a.verifyText('message', await a.signText('message', signing), signer.publicKey)).toBe(true);
});

test('rejects public/nonextractable/unsupported keys and invalid recipient keys', async () => {
  const nonextractable = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const unsupported = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 128 }, true, ['encrypt', 'decrypt']);
  for (const key of [recipient.publicKey, signer.publicKey, nonextractable, unsupported, null, {}]) {
    await expect(a.wrapKey(key as never, recipient.publicKey)).rejects.toBeInstanceOf(InvalidKeyError);
  }
  for (const key of [recipient.privateKey, signer.publicKey, secret]) {
    await expect(a.wrapKey(secret, key as never)).rejects.toBeInstanceOf(InvalidKeyError);
  }
  const wrapped = await a.wrapKey(secret, recipient.publicKey);
  for (const options of [undefined, null, {}, { purpose: 'public' }, { purpose: 1 }]) {
    await expect(a.unwrapKey(wrapped, recipient.privateKey, options as never)).rejects.toBeInstanceOf(InvalidArgumentError);
  }
  await expect(a.unwrapKey(wrapped, recipient.publicKey as never, { purpose: 'symmetric' })).rejects.toBeInstanceOf(InvalidKeyError);
});

test('wrong recipient, tampering and payload confusion fail uniformly', async () => {
  const wrapped = await a.wrapKey(secret, recipient.publicKey);
  await expect(a.unwrapKey(wrapped, other.privateKey, { purpose: 'symmetric' })).rejects.toBeInstanceOf(DecryptionError);
  const bad = wrapped.toBinary(); bad[bad.length - 1] = bad[bad.length - 1]! ^ 1;
  await expect(a.unwrapKey(EncryptedData.fromBinary(bad), recipient.privateKey, { purpose: 'symmetric' })).rejects.toBeInstanceOf(DecryptionError);
  await expect(a.decrypt(wrapped, recipient.privateKey)).rejects.toBeInstanceOf(DecryptionError);
  const ordinary = await a.encryptText(JSON.stringify(await s.exportKey(secret)), recipient.publicKey);
  await expect(a.unwrapKey(ordinary, recipient.privateKey, { purpose: 'symmetric' })).rejects.toBeInstanceOf(DecryptionError);
  const backup = await s.exportKeyWithPassword(secret, 'password');
  await expect(a.unwrapKey(backup, recipient.privateKey, { purpose: 'symmetric' })).rejects.toBeInstanceOf(DecryptionError);
  await expect(s.importKeyWithPassword(wrapped, 'password')).rejects.toBeInstanceOf(DecryptionError);
  const parts = ordinary.toJWE().split('.');
  parts[0] = b64(utf8(JSON.stringify({ alg: 'RSA-OAEP-256', enc: 'A256GCM', cty: 'jwk+json' })));
  await expect(a.unwrapKey(EncryptedData.fromJWE(parts.join('.')), recipient.privateKey, { purpose: 'symmetric' })).rejects.toBeInstanceOf(DecryptionError);
});

test('JOSE interoperability includes validation of decrypted key material', async () => {
  const publicKey = await importJWK(await a.exportKey(recipient.publicKey), 'RSA-OAEP-256');
  const privateKey = await importJWK(await a.exportKey(recipient.privateKey), 'RSA-OAEP-256');
  const jwk = await s.exportKey(secret);
  const wrapped = await a.wrapKey(secret, recipient.publicKey);
  const decoded = await compactDecrypt(wrapped.toJWE(), privateKey);
  expect(decoded.protectedHeader.cty).toBe('jwk+json');
  expect(JSON.parse(text(decoded.plaintext))).toEqual(jwk);
  const produce = async (value: Uint8Array) => EncryptedData.fromJWE(await new CompactEncrypt(value).setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM', cty: 'jwk+json' }).encrypt(publicKey));
  expect(await s.exportKey(await a.unwrapKey(await produce(utf8(JSON.stringify(jwk))), recipient.privateKey, { purpose: 'symmetric' }))).toEqual(jwk);
  for (const payload of [utf8('null'), utf8('invalid json'), new Uint8Array([255]), utf8(JSON.stringify({ ...jwk, key_ops: ['sign'] })), utf8(JSON.stringify({ ...jwk, k: 'AA' }))]) {
    await expect(a.unwrapKey(await produce(payload), recipient.privateKey, { purpose: 'symmetric' })).rejects.toBeInstanceOf(DecryptionError);
  }
  const publicPayload = await produce(utf8(JSON.stringify(await a.exportKey(other.publicKey))));
  await expect(a.unwrapKey(publicPayload, recipient.privateKey, { purpose: 'encryption' })).rejects.toBeInstanceOf(DecryptionError);
  const oversized = await new CompactEncrypt(new Uint8Array(32769)).setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM', cty: 'jwk+json' }).encrypt(publicKey);
  const unwrap = spyOn(crypto.subtle, 'unwrapKey');
  try {
    expect(() => EncryptedData.fromJWE(oversized)).toThrow(DecryptionError);
    expect(unwrap).not.toHaveBeenCalled();
  } finally { unwrap.mockRestore(); }
});

test('unwrap snapshots the expected purpose before asynchronous decryption', async () => {
  const wrapped = await a.wrapKey(secret, recipient.publicKey);
  const options: { purpose: 'symmetric' | 'signing' } = { purpose: 'symmetric' };
  const pending = a.unwrapKey(wrapped, recipient.privateKey, options); options.purpose = 'signing';
  expect((await pending).type).toBe('secret');
});
