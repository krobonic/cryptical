// This module is bundled with library imports externalized to built dist JavaScript.
import { symmetric, asymmetric } from '../../index.js';
import * as s from '../../src/symmetric.js';
import * as a from '../../src/asymmetric.js';
import type { EncryptionPublicKey, EncryptionPrivateKey, SigningPublicKey, SigningPrivateKey } from '../../src/types.js';
import fixture from '../fixtures/interop.json';
const message = '\ufeffnative interchange 世界 👩🏽‍💻\r\n', password = 'test only 密碼 🔐';
function check(value: boolean, label: string): void { if (!value) throw new Error(label); }
export interface Artifact {
  symmetric: JsonWebKey; encryptionPublic: JsonWebKey; encryptionPrivate: JsonWebKey;
  signingPublic: JsonWebKey; signingPrivate: JsonWebKey;
  dir: string; pbes: string; rsa: string; signature: string;
  symmetricBackup: string; encryptionBackup: string; signingBackup: string;
}
export type EncryptionArtifact = Pick<Artifact, 'symmetric' | 'encryptionPublic' | 'encryptionPrivate' | 'dir' | 'pbes' | 'rsa' | 'symmetricBackup' | 'encryptionBackup'>;
export async function produceEncryption(): Promise<EncryptionArtifact> {
  const key = await symmetric.generateKey(), recipient = await asymmetric.generateEncryptionKeyPair();
  return {
    symmetric: await s.exportKey(key), encryptionPublic: await a.exportKey(recipient.publicKey), encryptionPrivate: await a.exportKey(recipient.privateKey),
    dir: await s.encryptText(message, key), pbes: await s.encryptTextWithPassword(message, password), rsa: await a.encryptText(message, recipient.publicKey),
    symmetricBackup: await s.exportKeyWithPassword(key, password), encryptionBackup: await a.exportKeyWithPassword(recipient.privateKey, password),
  };
}
export async function produce(): Promise<Artifact> {
  const signer = await a.generateSigningKeyPair();
  return {
    ...await produceEncryption(), signingPublic: await a.exportKey(signer.publicKey), signingPrivate: await a.exportKey(signer.privateKey),
    signature: await a.signText(message, signer.privateKey), signingBackup: await a.exportKeyWithPassword(signer.privateKey, password),
  };
}
export async function consumeEncryption(artifact: EncryptionArtifact): Promise<void> {
  const key = await s.importKey(artifact.symmetric), rsa = await a.importEncryptionKey(artifact.encryptionPrivate) as EncryptionPrivateKey;
  const publicKey = await a.importEncryptionKey(artifact.encryptionPublic) as EncryptionPublicKey;
  check(await s.decryptText(artifact.dir, key) === message, 'dir');
  check(await s.decryptTextWithPassword(artifact.pbes, password) === message, 'pbes');
  check(await a.decryptText(artifact.rsa, rsa) === message, 'rsa');
  check(await a.decryptText(await a.encryptText(message, publicKey), rsa) === message, 'public JWK');
  check(await s.decryptText(artifact.dir, await s.importKeyWithPassword(artifact.symmetricBackup, password)) === message, 'symmetric backup');
  check(await a.decryptText(artifact.rsa, await a.importEncryptionKeyWithPassword(artifact.encryptionBackup, password)) === message, 'RSA backup');
}
export async function consume(artifact: Artifact): Promise<void> {
  await consumeEncryption(artifact);
  const signer = await a.importSigningKey(artifact.signingPrivate) as SigningPrivateKey;
  const verifier = await a.importSigningKey(artifact.signingPublic) as SigningPublicKey;
  check(await a.verifyText(message, artifact.signature, verifier), 'signature');
  check(await a.signText(message, signer) === artifact.signature, 'private signing JWK');
  check(await a.signText(message, await a.importSigningKeyWithPassword(artifact.signingBackup, password)) === artifact.signature, 'signing backup');
}
export async function adversarial(): Promise<void> {
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
  const symmetric = await s.importKey(fixture.jwe.symmetric);
  check(await s.decryptText(fixture.jwe.dir, symmetric) === fixture.jwe.message, 'saved dir fixture');
  check(await s.decryptTextWithPassword(fixture.jwe.password, fixture.jwe.secret) === fixture.jwe.message, 'saved password fixture');
  check(await a.decryptText(fixture.jwe.recipient, await a.importEncryptionKey(fixture.jwe.rsa)) === fixture.jwe.message, 'saved RSA fixture');
  const parts = fixture.jwe.dir.split('.'); parts[4] = 'AAAAAAAAAAAAAAAAAAAAAA';
  try { await s.decrypt(parts.join('.'), symmetric); throw new Error('accepted corruption'); }
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
