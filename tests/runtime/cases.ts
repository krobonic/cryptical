// This module is bundled with library imports externalized to built dist JavaScript.
import { EncryptedData, symmetric, asymmetric, InvalidKeyError } from '../../index.js';
import * as s from '../../src/symmetric.js';
import * as a from '../../src/asymmetric.js';
import type { EncryptionPublicKey, EncryptionPrivateKey, SigningPublicKey, SigningPrivateKey } from '../../src/types.js';
import fixture from '../fixtures/interop.json';
import leadingZeroFixture from '../fixtures/rsa-leading-zero.json';
const message = '\ufeffnative interchange 世界 👩🏽‍💻\r\n', password = 'test only 密碼 🔐';
function check(value: boolean, label: string): void { if (!value) throw new Error(label); }
export interface Artifact {
  wrappingKey: JsonWebKey;
  symmetric: JsonWebKey; encryptionPublic: JsonWebKey; encryptionPrivate: JsonWebKey;
  signingPublic: JsonWebKey; signingPrivate: JsonWebKey;
  binary: Record<string, number[]>;
  dir: string; pbes: string; rsa: string; signature: string;
  symmetricBackup: string; encryptionBackup: string; signingBackup: string;
  sharedSymmetric: string; sharedEncryption: string; sharedSigning: string;
  wrappedSymmetric: string; wrappedEncryption: string; wrappedSigning: string;
}
export type EncryptionArtifact = Pick<Artifact, 'wrappingKey' | 'sharedSymmetric' | 'sharedEncryption' | 'binary' | 'symmetric' | 'encryptionPublic' | 'encryptionPrivate' | 'dir' | 'pbes' | 'rsa' | 'symmetricBackup' | 'encryptionBackup' | 'wrappedSymmetric' | 'wrappedEncryption'>;
export async function produceEncryption(): Promise<EncryptionArtifact> {
  const wrappingKey = await s.generateKey();
  const key = await symmetric.generateKey(), recipient = await asymmetric.generateEncryptionKeyPair();
  const output = {
    wrappingKey: await s.exportKey(wrappingKey),
    sharedSymmetric: (await s.wrapKey(key, wrappingKey)).toJWE(), sharedEncryption: (await s.wrapKey(recipient.privateKey, wrappingKey)).toJWE(),
    symmetric: await s.exportKey(key), encryptionPublic: await a.exportKey(recipient.publicKey), encryptionPrivate: await a.exportKey(recipient.privateKey),
    dir: (await s.encryptText(message, key)).toJWE(), pbes: (await s.encryptTextWithPassword(message, password)).toJWE(), rsa: (await a.encryptText(message, recipient.publicKey)).toJWE(),
    wrappedSymmetric: (await a.wrapKey(key, recipient.publicKey)).toJWE(), wrappedEncryption: (await a.wrapKey(recipient.privateKey, recipient.publicKey)).toJWE(),
    symmetricBackup: (await s.exportKeyWithPassword(key, password)).toJWE(), encryptionBackup: (await a.exportKeyWithPassword(recipient.privateKey, password)).toJWE(),
  };
  const binary = Object.fromEntries((['dir', 'pbes', 'rsa', 'symmetricBackup', 'encryptionBackup', 'wrappedSymmetric', 'wrappedEncryption', 'sharedSymmetric', 'sharedEncryption'] as const).map(name => [name, Array.from(EncryptedData.fromJWE(output[name]).toBinary())]));
  return { ...output, binary };
}
export async function produce(): Promise<Artifact> {
  const signer = await a.generateSigningKeyPair(), encryption = await produceEncryption();
  return {
    sharedSigning: (await s.wrapKey(signer.privateKey, await s.importKey(encryption.wrappingKey))).toJWE(),
    wrappedSigning: (await a.wrapKey(signer.privateKey, await a.importEncryptionKey(encryption.encryptionPublic) as EncryptionPublicKey)).toJWE(),
    ...encryption, signingPublic: await a.exportKey(signer.publicKey), signingPrivate: await a.exportKey(signer.privateKey),
    signature: await a.signText(message, signer.privateKey), signingBackup: (await a.exportKeyWithPassword(signer.privateKey, password)).toJWE(),
  };
}
export async function consumeEncryption(artifact: EncryptionArtifact): Promise<void> {
  let operation = 'encryption JWK import';
  try {
    const key = await s.importKey(artifact.symmetric), rsa = await a.importEncryptionKey(artifact.encryptionPrivate) as EncryptionPrivateKey;
    const wrappingKey = await s.importKey(artifact.wrappingKey);
    const publicKey = await a.importEncryptionKey(artifact.encryptionPublic) as EncryptionPublicKey;
    for (const format of ['jwe', 'binary'] as const) {
      const parse = (name: 'dir' | 'pbes' | 'rsa' | 'symmetricBackup' | 'encryptionBackup' | 'wrappedSymmetric' | 'wrappedEncryption' | 'sharedSymmetric' | 'sharedEncryption') => {
        const data = format === 'jwe' ? EncryptedData.fromJWE(artifact[name]) : EncryptedData.fromBinary(new Uint8Array(artifact.binary[name]!));
        check(data.toJWE() === artifact[name], 'exact JWE preservation');
        return data;
      };
      operation = 'shared symmetric key';
      check(await s.decryptText(parse('dir'), await s.unwrapKey(parse('sharedSymmetric'), wrappingKey, { purpose: 'symmetric' })) === message, 'shared symmetric key');
      operation = 'shared encryption key';
      check(await a.decryptText(parse('rsa'), await s.unwrapKey(parse('sharedEncryption'), wrappingKey, { purpose: 'encryption' })) === message, 'shared encryption key');
      operation = 'RSA-wrapped symmetric key';
      const unwrappedSymmetric = await a.unwrapKey(parse('wrappedSymmetric'), rsa, { purpose: 'symmetric' });
      operation = 'RSA-wrapped encryption key';
      const unwrappedEncryption = await a.unwrapKey(parse('wrappedEncryption'), rsa, { purpose: 'encryption' });
      operation = 'wrapped symmetric key';
      check(await s.decryptText(parse('dir'), unwrappedSymmetric) === message, 'wrapped symmetric key');
      operation = 'wrapped encryption key';
      check(await a.decryptText(parse('rsa'), unwrappedEncryption) === message, 'wrapped encryption key');
      operation = 'dir';
      check(await s.decryptText(parse('dir'), key) === message, 'dir');
      operation = 'pbes';
      check(await s.decryptTextWithPassword(parse('pbes'), password) === message, 'pbes');
      operation = 'rsa';
      check(await a.decryptText(parse('rsa'), rsa) === message, 'rsa');
      operation = 'symmetric backup';
      check(await s.decryptText(parse('dir'), await s.importKeyWithPassword(parse('symmetricBackup'), password)) === message, 'symmetric backup');
      operation = 'RSA backup';
      check(await a.decryptText(parse('rsa'), await a.importEncryptionKeyWithPassword(parse('encryptionBackup'), password)) === message, 'RSA backup');
    }
    operation = 'public JWK';
    check(await a.decryptText(await a.encryptText(message, publicKey), rsa) === message, 'public JWK');
  } catch (error) { throw new Error(`${operation}: ${String(error)}`, { cause: error }); }
}

export async function consume(artifact: Artifact): Promise<void> {
  let operation = 'encryption';
  try {
    await consumeEncryption(artifact);
    operation = 'signing JWK import';
    const signer = await a.importSigningKey(artifact.signingPrivate) as SigningPrivateKey;
    const verifier = await a.importSigningKey(artifact.signingPublic) as SigningPublicKey;
    const recipient = await a.importEncryptionKey(artifact.encryptionPrivate) as EncryptionPrivateKey;
    operation = 'shared signing key';
    const sharedSigning = EncryptedData.fromJWE(artifact.sharedSigning);
    for (const [i, data] of [sharedSigning, EncryptedData.fromBinary(sharedSigning.toBinary())].entries()) {
      operation = `shared signing key (${i === 0 ? 'JWE' : 'binary'})`;
      const unwrapped = await s.unwrapKey(data, await s.importKey(artifact.wrappingKey), { purpose: 'signing' });
      check(await a.signText(message, unwrapped) === artifact.signature, 'shared signing key');
    }
    operation = 'RSA-wrapped signing key';
    const wrappedSigning = EncryptedData.fromJWE(artifact.wrappedSigning);
    for (const [i, data] of [wrappedSigning, EncryptedData.fromBinary(wrappedSigning.toBinary())].entries()) {
      operation = `RSA-wrapped signing key (${i === 0 ? 'JWE' : 'binary'})`;
      const unwrapped = await a.unwrapKey(data, recipient, { purpose: 'signing' });
      check(await a.signText(message, unwrapped) === artifact.signature, 'wrapped signing key');
    }
    operation = 'signature verification';
    check(await a.verifyText(message, artifact.signature, verifier), 'signature');
    operation = 'private signing JWK';
    check(await a.signText(message, signer) === artifact.signature, 'private signing JWK');
    operation = 'signing backup';
    check(await a.signText(message, await a.importSigningKeyWithPassword(EncryptedData.fromBinary(EncryptedData.fromJWE(artifact.signingBackup).toBinary()), password)) === artifact.signature, 'signing backup');
  } catch (error) { throw new Error(`${operation}: ${String(error)}`, { cause: error }); }
}

/** Fixed CEKs make WebKit/libgcrypt leading-zero truncation deterministic. */
export async function rsaLeadingZeros(): Promise<void> {
  // Import natively to isolate CEK preservation from the randomized RSA import check.
  const key = await crypto.subtle.importKey('jwk', fixture.jwe.rsa, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['unwrapKey']) as EncryptionPrivateKey;
  for (const { leadingZeros, jwe } of leadingZeroFixture.vectors) {
    const value = EncryptedData.fromJWE(jwe);
    for (const [i, data] of [value, EncryptedData.fromBinary(value.toBinary())].entries()) {
      const label = `RSA-OAEP CEK with ${leadingZeros} leading zero bytes (${i === 0 ? 'JWE' : 'binary'})`;
      try { check(await a.decryptText(data, key) === leadingZeroFixture.message, label); }
      catch (error) { throw new Error(`${label}: ${String(error)}`, { cause: error }); }
    }
  }
}
export async function adversarial(): Promise<void> {
  await rsaLeadingZeros();
  // Run before Ed25519 vectors so RSA is checked even on encryption-only providers.
  const malformedRsa = { ...fixture.jwe.rsa, d: 'AQ', p: 'AQ', q: 'AQ', dp: 'AQ', dq: 'AQ', qi: 'AQ' };
  try {
    await a.importEncryptionKey(malformedRsa);
    throw new Error('accepted unusable RSA private JWK');
  } catch (error) { check(error instanceof InvalidKeyError, 'unusable RSA private JWK error'); }
  const f = fixture.ed25519;
  const hex = (value: string) => Uint8Array.from(value.match(/../g) ?? [], v => parseInt(v, 16));
  const encode = (value: Uint8Array) => btoa(String.fromCharCode(...value)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const key = await a.importSigningKey({ kty: 'OKP', crv: 'Ed25519', x: encode(hex(f.publicKey)) }) as SigningPublicKey;
  check(await a.verify(new Uint8Array(), hex(f.signature), key), 'RFC8032');
  const sig = hex(f.signature);
  sig.set(hex('edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010'), 32);
  check(!await a.verify(new Uint8Array(), sig, key), 'noncanonical S');
  sig.set(hex(f.signature));
  sig.fill(255, 0, 32);
  check(!await a.verify(new Uint8Array(), sig, key), 'noncanonical R');
  check(!await a.verifyText('', 'AA==', key), 'noncanonical base64');
  const privateJwk = { kty: 'OKP', crv: 'Ed25519', x: encode(hex(f.publicKey)), d: encode(hex(f.seed)) };
  const other = await a.exportKey((await a.generateSigningKeyPair()).privateKey);
  for (const alg of [undefined, 'EdDSA', 'Ed25519']) {
    const imported = await a.importSigningKey({ ...privateJwk, alg });
    const exported = await a.exportKey(imported);
    check(exported.x === privateJwk.x && exported.d === privateJwk.d && exported.alg === 'EdDSA', 'private Ed25519 JWK preservation');
    check(encode(await a.sign(new Uint8Array(), imported)) === encode(hex(f.signature)), 'imported private Ed25519 signature');
    for (const mismatch of [{ x: other.x }, { d: other.d }]) {
      try {
        await a.importSigningKey({ ...privateJwk, alg, ...mismatch });
        throw new Error('accepted inconsistent Ed25519 private JWK');
      } catch (error) { check(error instanceof InvalidKeyError, 'inconsistent Ed25519 private JWK error'); }
    }
  }
  const symmetric = await s.importKey(fixture.jwe.symmetric);
  check(await s.decryptText(EncryptedData.fromBinary(EncryptedData.fromJWE(fixture.jwe.dir).toBinary()), symmetric) === fixture.jwe.message, 'saved dir fixture');
  check(await s.decryptTextWithPassword(EncryptedData.fromBinary(EncryptedData.fromJWE(fixture.jwe.password).toBinary()), fixture.jwe.secret) === fixture.jwe.message, 'saved password fixture');
  check(await a.decryptText(EncryptedData.fromBinary(EncryptedData.fromJWE(fixture.jwe.recipient).toBinary()), await a.importEncryptionKey(fixture.jwe.rsa)) === fixture.jwe.message, 'saved RSA fixture');
  const parts = fixture.jwe.dir.split('.'); parts[4] = 'AAAAAAAAAAAAAAAAAAAAAA';
  try { await s.decrypt(EncryptedData.fromBinary(EncryptedData.fromJWE(parts.join('.')).toBinary()), symmetric); throw new Error('accepted corruption'); }
  catch (error) { check(error instanceof Error && error.name === 'DecryptionError', 'uniform decryption error'); }
}
/** Run on named devices for release records; milliseconds, after one warm-up. */
export async function benchmark(): Promise<{ encryptMedian: number; encryptMax: number; decryptMedian: number; decryptMax: number }> {
  const enc: number[] = [], dec: number[] = [];
  for (let i = -1; i < 10; i++) {
    const start = performance.now(), sealed = await s.encryptTextWithPassword(message, password), middle = performance.now();
    await s.decryptTextWithPassword(sealed, password);
    if (i >= 0) { enc.push(middle - start); dec.push(performance.now() - middle); }
  }
  const median = (values: number[]) => { values.sort((a, b) => a - b); return (values[4]! + values[5]!) / 2; };
  return { encryptMedian: median(enc), encryptMax: Math.max(...enc), decryptMedian: median(dec), decryptMax: Math.max(...dec) };
}
