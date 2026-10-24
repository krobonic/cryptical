import { expect, test } from 'bun:test';
import { asymmetric as a, InvalidKeyError } from '../index';

test('explicit signing imports restore JSON keys with usable public and private halves', async () => {
  const original = await a.generateSigningKeyPair();
  const privateJwk = await a.exportKey(original.privateKey);
  const publicJwk = await a.exportKey(original.publicKey);
  const pair = await a.importSigningKeyPair(JSON.parse(JSON.stringify(privateJwk)));
  const publicKey = await a.importSigningPublicKey(JSON.parse(JSON.stringify(publicJwk)));
  expect(await a.exportKey(pair.privateKey)).toEqual(privateJwk);
  expect(await a.exportKey(pair.publicKey)).toEqual(publicJwk);
  expect(pair.publicKey.usages).toEqual(['verify']);
  const signature = await a.signText('restored', pair.privateKey);
  expect(await a.verifyText('restored', signature, publicKey)).toBe(true);
  expect(await a.verifyText('restored', signature, pair.publicKey)).toBe(true);
  await expect(a.importSigningPublicKey(privateJwk)).rejects.toBeInstanceOf(InvalidKeyError);
  await expect(a.importSigningKeyPair(publicJwk)).rejects.toBeInstanceOf(InvalidKeyError);
  const other = await a.exportKey((await a.generateSigningKeyPair()).publicKey);
  await expect(a.importSigningKeyPair({ ...privateJwk, x: other.x })).rejects.toBeInstanceOf(InvalidKeyError);
});

test('explicit encryption imports restore JSON keys with usable public and private halves', async () => {
  const original = await a.generateEncryptionKeyPair();
  const privateJwk = await a.exportKey(original.privateKey);
  const publicJwk = await a.exportKey(original.publicKey);
  const pair = await a.importEncryptionKeyPair(JSON.parse(JSON.stringify(privateJwk)));
  const publicKey = await a.importEncryptionPublicKey(JSON.parse(JSON.stringify(publicJwk)));
  expect(await a.exportKey(pair.privateKey)).toEqual(privateJwk);
  expect(await a.exportKey(pair.publicKey)).toEqual(publicJwk);
  expect([...pair.publicKey.usages].sort()).toEqual(['encrypt', 'wrapKey']);
  for (const key of [publicKey, pair.publicKey]) {
    expect(await a.decryptText(await a.encryptText('restored', key), pair.privateKey)).toBe('restored');
  }
  await expect(a.importEncryptionPublicKey(privateJwk)).rejects.toBeInstanceOf(InvalidKeyError);
  await expect(a.importEncryptionKeyPair(publicJwk)).rejects.toBeInstanceOf(InvalidKeyError);
  await expect(a.importEncryptionKeyPair({ ...privateJwk, n: 'invalid' })).rejects.toBeInstanceOf(InvalidKeyError);
  await expect(a.importSigningPublicKey(publicJwk)).rejects.toBeInstanceOf(InvalidKeyError);
  await expect(a.importSigningKeyPair(privateJwk)).rejects.toBeInstanceOf(InvalidKeyError);
  const signer = await a.generateSigningKeyPair();
  await expect(a.importEncryptionPublicKey(await a.exportKey(signer.publicKey))).rejects.toBeInstanceOf(InvalidKeyError);
  await expect(a.importEncryptionKeyPair(await a.exportKey(signer.privateKey))).rejects.toBeInstanceOf(InvalidKeyError);
});
