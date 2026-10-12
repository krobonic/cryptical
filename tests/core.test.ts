import { describe, expect, test } from 'bun:test';
import { symmetric as s, asymmetric as a, InvalidArgumentError } from '../index';
import type { EncryptionPrivateKey, EncryptionPublicKey, SigningPrivateKey, SigningPublicKey } from '../src/types';
describe('public API', () => {
  test('text, empty input, BOM, whitespace and binary views round-trip', async () => {
    const key = await s.generateKey();
    for (const value of ['', '\ufeff hello\r\n世界 👩🏽‍💻 ', 'é', 'e\u0301']) expect(await s.decryptText(await s.encryptText(value, key), key)).toBe(value);
    const input = new Uint8Array([99, 0, 255, 99]).subarray(1, 3);
    expect(await s.decrypt(await s.encrypt(input, key), key)).toEqual(input);
    expect(await s.encryptText('same', key)).not.toBe(await s.encryptText('same', key));
    expect(await s.exportKey(await s.importKey(await s.exportKey(key)))).toEqual(await s.exportKey(key));
  });
  test('copies bytes synchronously', async () => {
    const key = await s.generateKey(), data = new Uint8Array([1, 2, 3]);
    const pending = s.encrypt(data, key); data.fill(0);
    expect(await s.decrypt(await pending, key)).toEqual(new Uint8Array([1, 2, 3]));
  });
  test('passwords and protected symmetric keys', async () => {
    const password = '  密碼🔐\ufeff  ', key = await s.generateKey();
    expect(await s.decryptTextWithPassword(await s.encryptTextWithPassword('\ufeff', password), password)).toBe('\ufeff');
    expect(await s.decryptWithPassword(await s.encryptWithPassword(new Uint8Array(), password), password)).toEqual(new Uint8Array());
    const restored = await s.importKeyWithPassword(await s.exportKeyWithPassword(key, password), password);
    expect(await s.exportKey(restored)).toEqual(await s.exportKey(key));
  });
  test('recipient encryption, signing and portable key backups', async () => {
    const recipient = await a.generateEncryptionKeyPair(), signer = await a.generateSigningKeyPair();
    const pub = await a.exportKey(recipient.publicKey), priv = await a.exportKey(recipient.privateKey);
    expect(pub.d).toBeUndefined();
    const publicKey = await a.importEncryptionKey(pub) as EncryptionPublicKey;
    const privateKey = await a.importEncryptionKey(priv) as EncryptionPrivateKey;
    expect(await a.decryptText(await a.encryptText('message', publicKey), privateKey)).toBe('message');
    const backup = await a.exportKeyWithPassword(privateKey, 'recovery password');
    expect(await a.exportKey(await a.importEncryptionKeyWithPassword(backup, 'recovery password'))).toEqual(priv);
    const signKey = await a.importSigningKey(await a.exportKey(signer.privateKey)) as SigningPrivateKey;
    const verifyKey = await a.importSigningKey(await a.exportKey(signer.publicKey)) as SigningPublicKey;
    const signature = await a.signText('message', signKey);
    expect(await a.verifyText('message', signature, verifyKey)).toBe(true);
    expect(await a.verifyText('changed', signature, verifyKey)).toBe(false);
    expect((await a.sign(new Uint8Array(), signKey)).length).toBe(64);
    expect(await a.exportKey(await a.importSigningKeyWithPassword(await a.exportKeyWithPassword(signKey, 'password'), 'password'))).toEqual(await a.exportKey(signKey));
  }, 30000);
  test('invalid text is never replaced', async () => {
    const key = await s.generateKey();
    for (const bad of ['\ud800', '\udc00', 'a\ud800b']) await expect(s.encryptText(bad, key)).rejects.toBeInstanceOf(InvalidArgumentError);
  });
});
