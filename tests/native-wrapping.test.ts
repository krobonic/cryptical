import { expect, test, spyOn } from 'bun:test';
import { CompactEncrypt } from 'jose';
import { symmetric as s, asymmetric as a, EncryptedData, InvalidKeyError, DecryptionError } from '../index';
import type { EncryptionPublicKey, EncryptionPrivateKey } from '../src/types';
import { seal } from '../src/internal/jwe';

test('generated and imported general-purpose keys have exact wrapping usages', async () => {
  const secret = await s.generateKey(), rsa = await a.generateEncryptionKeyPair();
  for (const [key, usages] of [[secret, ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']], [rsa.publicKey, ['encrypt', 'wrapKey']], [rsa.privateKey, ['decrypt', 'unwrapKey']]] as const) {
    expect([...key.usages].sort()).toEqual([...usages].sort());
    const jwk = await crypto.subtle.exportKey('jwk', key);
    const load = (jwk: JsonWebKey) => key.type === 'secret' ? s.importKey(jwk) : a.importEncryptionKey(jwk);
    expect((await load(jwk)).usages).toEqual(key.usages);
    const { key_ops, ...unspecified } = jwk;
    expect((await load(unspecified)).usages).toEqual(key.usages);
    for (const ops of [[], [usages[0]], [...usages, usages[0]]]) {
      await expect(load({ ...jwk, key_ops: ops })).rejects.toBeInstanceOf(InvalidKeyError);
    }
  }
});

test('native wrapping APIs handle payloads and CEKs with minimal temporary usages', async () => {
  const secret = await s.generateKey(), rsa = await a.generateEncryptionKeyPair();
  const wrap = spyOn(crypto.subtle, 'wrapKey'), unwrap = spyOn(crypto.subtle, 'unwrapKey');
  const encrypt = spyOn(crypto.subtle, 'encrypt'), decrypt = spyOn(crypto.subtle, 'decrypt');
  try {
    const direct = await s.wrapKey(secret, secret);
    await s.unwrapKey(direct, secret, { purpose: 'symmetric' });
    const recipient = await a.wrapKey(secret, rsa.publicKey);
    await a.unwrapKey(recipient, rsa.privateKey, { purpose: 'symmetric' });
    expect(encrypt).not.toHaveBeenCalled();
    expect(decrypt).not.toHaveBeenCalled();
    expect(wrap.mock.calls.map(call => call[0])).toEqual(['jwk', 'raw', 'jwk']);
    expect(wrap.mock.calls[1]![1].usages).toEqual(['wrapKey']);
    expect(unwrap.mock.calls.map(call => call[0])).toEqual(['raw', 'raw', 'raw']);
    expect(unwrap.mock.calls[1]![6]).toEqual(['unwrapKey']);
    expect(unwrap.mock.calls[1]![5]).toBe(false);
    await a.decryptText(await a.encryptText('data', rsa.publicKey), rsa.privateKey);
    expect(wrap.mock.calls[3]![1].usages).toEqual(['encrypt']);
    expect(unwrap.mock.calls[3]![6]).toEqual(['decrypt']);
    await s.decryptTextWithPassword(await s.encryptTextWithPassword('password data', 'password'), 'password');
    expect(wrap.mock.calls[4]![3]).toBe('AES-KW');
    expect(wrap.mock.calls[4]![2].usages).toEqual(['wrapKey']);
    expect(unwrap.mock.calls[4]![2].usages).toEqual(['unwrapKey']);
  } finally { wrap.mockRestore(); unwrap.mockRestore(); encrypt.mockRestore(); decrypt.mockRestore(); }
});

test('RSA nonextractable wrap-only and unwrap-only recipients work; encrypt/decrypt-only do not', async () => {
  const rsa = await a.generateEncryptionKeyPair(), secret = await s.generateKey();
  const publicJwk = await a.exportKey(rsa.publicKey), privateJwk = await a.exportKey(rsa.privateKey);
  const algorithm = { name: 'RSA-OAEP', hash: 'SHA-256' };
  const pub = await crypto.subtle.importKey('jwk', publicJwk, algorithm, false, ['wrapKey']) as EncryptionPublicKey;
  const priv = await crypto.subtle.importKey('jwk', privateJwk, algorithm, false, ['unwrapKey']) as EncryptionPrivateKey;
  expect(await s.exportKey(await a.unwrapKey(await a.wrapKey(secret, pub), priv, { purpose: 'symmetric' }))).toEqual(await s.exportKey(secret));
  expect(await a.decryptText(await a.encryptText('data', pub), priv)).toBe('data');
  const encryptOnly = await crypto.subtle.importKey('jwk', publicJwk, algorithm, false, ['encrypt']) as EncryptionPublicKey;
  const decryptOnly = await crypto.subtle.importKey('jwk', privateJwk, algorithm, false, ['decrypt']) as EncryptionPrivateKey;
  await expect(a.wrapKey(secret, encryptOnly)).rejects.toBeInstanceOf(InvalidKeyError);
  await expect(a.unwrapKey(await a.wrapKey(secret, pub), decryptOnly, { purpose: 'symmetric' })).rejects.toBeInstanceOf(InvalidKeyError);
});

test('native unwrap retains original metadata and rejects malformed payloads through both envelopes', async () => {
  const secret = await s.generateKey(), rsa = await a.generateEncryptionKeyPair(), jwk = await s.exportKey(secret);
  const invalid = [new Uint8Array(), new Uint8Array([255]), ...[
    null, [], { ...jwk, alg: 'A128GCM' }, { ...jwk, use: 'sig' }, { ...jwk, ext: false },
    { ...jwk, key_ops: ['encrypt', 'decrypt'] }, { ...jwk, key_ops: [...jwk.key_ops!, 'encrypt'] },
    { ...jwk, x: 'AA' }, { ...jwk, k: jwk.k + '=' },
  ].map(value => new TextEncoder().encode(JSON.stringify(value)))];
  for (const payload of invalid) {
    const direct = await new CompactEncrypt(payload).setProtectedHeader({ alg: 'dir', enc: 'A256GCM', cty: 'jwk+json' }).encrypt(secret);
    const recipient = await new CompactEncrypt(payload).setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM', cty: 'jwk+json' }).encrypt(rsa.publicKey);
    await expect(s.unwrapKey(EncryptedData.fromJWE(direct), secret, { purpose: 'symmetric' })).rejects.toBeInstanceOf(DecryptionError);
    await expect(a.unwrapKey(EncryptedData.fromJWE(recipient), rsa.privateKey, { purpose: 'symmetric' })).rejects.toBeInstanceOf(DecryptionError);
  }
});

test('RSA rejects valid native AES keys of the wrong CEK length', async () => {
  const rsa = await a.generateEncryptionKeyPair();
  for (const length of [128, 192]) {
    const cek = await crypto.subtle.generateKey({ name: 'AES-GCM', length }, true, ['encrypt']);
    const wrapped = new Uint8Array(await crypto.subtle.wrapKey('raw', cek, rsa.publicKey, 'RSA-OAEP'));
    for (const cty of [undefined, 'jwk+json'] as const) {
      const value = await seal(new TextEncoder().encode('{}'), cek, { alg: 'RSA-OAEP-256', enc: 'A256GCM', ...(cty ? { cty } : {}) }, wrapped);
      await expect(cty ? a.unwrapKey(value, rsa.privateKey, { purpose: 'symmetric' }) : a.decrypt(value, rsa.privateKey)).rejects.toBeInstanceOf(DecryptionError);
    }
  }
});
