import { expect, test } from 'bun:test';
import { CompactEncrypt } from 'jose';
import { asymmetric as a, symmetric as s, EncryptedData, InvalidKeyError, DecryptionError } from '../index';
import { utf8 } from '../src/internal/encoding';

test('private Ed25519 imports preserve matching x/d and reject mismatches with either algorithm label', async () => {
  const first = await a.generateSigningKeyPair(), second = await a.generateSigningKeyPair();
  const jwk = await a.exportKey(first.privateKey), other = await a.exportKey(second.privateKey);
  for (const alg of [undefined, 'EdDSA', 'Ed25519']) {
    const supplied = { ...jwk, alg };
    const imported = await a.importSigningKey(supplied);
    expect(await a.exportKey(imported)).toEqual(jwk);
    expect(await a.verifyText('imported', await a.signText('imported', imported), first.publicKey)).toBe(true);
    await expect(a.importSigningKey({ ...supplied, x: other.x })).rejects.toBeInstanceOf(InvalidKeyError);
    await expect(a.importSigningKey({ ...supplied, d: other.d })).rejects.toBeInstanceOf(InvalidKeyError);
    expect(supplied.alg).toBe(alg);
  }
});

test('protected signing imports reject mismatched x/d and restore valid private JWKs', async () => {
  const signer = await a.generateSigningKeyPair(), other = await a.generateSigningKeyPair();
  const jwk = await a.exportKey(signer.privateKey), otherJwk = await a.exportKey(other.privateKey);
  const wrappingKey = await s.generateKey(), recipient = await a.generateEncryptionKeyPair();
  const password = 'test password';
  for (const alg of ['EdDSA', 'Ed25519']) {
    for (const valid of [true, false]) {
      const payload = utf8(JSON.stringify({ ...jwk, alg, x: valid ? jwk.x : otherJwk.x }));
      const direct = await new CompactEncrypt(payload).setProtectedHeader({ alg: 'dir', enc: 'A256GCM', cty: 'jwk+json' }).encrypt(wrappingKey);
      const rsa = await new CompactEncrypt(payload).setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM', cty: 'jwk+json' }).encrypt(recipient.publicKey);
      const backup = await new CompactEncrypt(payload).setProtectedHeader({ alg: 'PBES2-HS512+A256KW', enc: 'A256GCM', cty: 'jwk+json' }).setKeyManagementParameters({ p2c: 220000 }).encrypt(utf8(password));
      for (const restore of [
        () => s.unwrapKey(EncryptedData.fromJWE(direct), wrappingKey, { purpose: 'signing' }),
        () => a.unwrapKey(EncryptedData.fromJWE(rsa), recipient.privateKey, { purpose: 'signing' }),
        () => a.importSigningKeyWithPassword(EncryptedData.fromJWE(backup), password),
      ]) {
        if (valid) {
          const restored = await restore();
          expect(await a.exportKey(restored)).toEqual(jwk);
          expect(await a.verifyText('restored', await a.signText('restored', restored), signer.publicKey)).toBe(true);
        } else await expect(restore()).rejects.toBeInstanceOf(DecryptionError);
      }
    }
  }
});
