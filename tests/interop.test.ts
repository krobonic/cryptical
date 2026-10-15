import { expect, test } from 'bun:test';
import { CompactEncrypt, compactDecrypt, importJWK } from 'jose';
import { EncryptedData, symmetric as s, asymmetric as a } from '../index';
import { b64, utf8, text, unb64 } from '../src/internal/encoding';
import fixture from './fixtures/interop.json';
import { rsaLeadingZeros } from './runtime/cases';
import type { EncryptionPrivateKey, SigningPublicKey } from '../src/types';
const password = 'portable password 密碼', message = '\ufeffinteroperable 🌍';
const options = { keyManagementAlgorithms: ['PBES2-HS512+A256KW'], maxPBES2Count: 1000000 };
test('independent JOSE consumes and produces all three suites', async () => {
  const key = await s.generateKey(), jwk = await s.exportKey(key), raw = unb64(jwk.k!, 32);
  expect(text((await compactDecrypt((await s.encryptText(message, key)).toJWE(), raw)).plaintext)).toBe(message);
  expect(await s.decryptText(EncryptedData.fromJWE(await new CompactEncrypt(utf8(message)).setProtectedHeader({ alg: 'dir', enc: 'A256GCM' }).encrypt(raw)), key)).toBe(message);
  const rsa = await a.generateEncryptionKeyPair();
  const josePrivate = await importJWK(await a.exportKey(rsa.privateKey), 'RSA-OAEP-256');
  const josePublic = await importJWK(await a.exportKey(rsa.publicKey), 'RSA-OAEP-256');
  expect(text((await compactDecrypt((await a.encryptText(message, rsa.publicKey)).toJWE(), josePrivate)).plaintext)).toBe(message);
  expect(await a.decryptText(EncryptedData.fromJWE(await new CompactEncrypt(utf8(message)).setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM' }).encrypt(josePublic)), rsa.privateKey)).toBe(message);
  expect(text((await compactDecrypt((await s.encryptTextWithPassword(message, password)).toJWE(), utf8(password), options)).plaintext)).toBe(message);
  for (const [p2c, length] of [[220000, 16], [1000000, 64]] as const) {
    const value = await new CompactEncrypt(utf8(message)).setProtectedHeader({ alg: 'PBES2-HS512+A256KW', enc: 'A256GCM' }).setKeyManagementParameters({ p2c, p2s: crypto.getRandomValues(new Uint8Array(length)) }).encrypt(utf8(password));
    expect(await s.decryptTextWithPassword(EncryptedData.fromJWE(value), password)).toBe(message);
  }
  const backup = await s.exportKeyWithPassword(key, password);
  expect(JSON.parse(text((await compactDecrypt(backup.toJWE(), utf8(password), options)).plaintext))).toEqual(jwk);
}, 30000);
test('RFC 8032 exact detached signature and invalid encodings', async () => {
  const f = fixture.ed25519;
  const hex = (s: string) => Uint8Array.from(s.match(/../g) ?? [], n => parseInt(n, 16));
  const publicJwk = { kty: 'OKP', crv: 'Ed25519', x: b64(hex(f.publicKey)) };
  const privateKey = await a.importSigningKey({ ...publicJwk, d: b64(hex(f.seed)) });
  const publicKey = await a.importSigningKey(publicJwk) as SigningPublicKey;
  expect(await a.sign(hex(f.message), privateKey)).toEqual(hex(f.signature));
  expect(await a.verify(hex(f.message), hex(f.signature), publicKey)).toBe(true);
  // Noncanonical S=L (group order), and S with its top bit set, must fail.
  const order = hex('edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010');
  const invalid = hex(f.signature); invalid.set(order, 32);
  expect(await a.verify(new Uint8Array(), invalid, publicKey)).toBe(false);
  invalid.fill(255, 32);
  expect(await a.verify(new Uint8Array(), invalid, publicKey)).toBe(false);
});
test('preserved independent encrypted fixtures', async () => {
  const f = fixture as typeof fixture & { jwe: { symmetric: JsonWebKey; rsa: JsonWebKey; dir: string; recipient: string; password: string; secret: string; message: string } };
  const key = await s.importKey(f.jwe.symmetric);
  expect(await s.decryptText(EncryptedData.fromJWE(f.jwe.dir), key)).toBe(f.jwe.message);
  expect(await a.decryptText(EncryptedData.fromJWE(f.jwe.recipient), await a.importEncryptionKey(f.jwe.rsa) as EncryptionPrivateKey)).toBe(f.jwe.message);
  expect(await s.decryptTextWithPassword(EncryptedData.fromJWE(f.jwe.password), f.jwe.secret)).toBe(f.jwe.message);
});

test('RSA-OAEP preserves CEKs with one, multiple, or all leading zero bytes in JWE and binary', async () => {
  await rsaLeadingZeros();
});
