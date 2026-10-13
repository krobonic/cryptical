// This module is bundled with library imports externalized to built dist JavaScript.
import { EncryptedData, symmetric, asymmetric } from '../../index.js';
import * as s from '../../src/symmetric.js';
import * as a from '../../src/asymmetric.js';
import type { EncryptionPublicKey, EncryptionPrivateKey, SigningPublicKey, SigningPrivateKey } from '../../src/types.js';
import fixture from '../fixtures/interop.json';
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
  const key = await s.importKey(artifact.symmetric), rsa = await a.importEncryptionKey(artifact.encryptionPrivate) as EncryptionPrivateKey;
  const wrappingKey = await s.importKey(artifact.wrappingKey);
  const publicKey = await a.importEncryptionKey(artifact.encryptionPublic) as EncryptionPublicKey;
  for (const format of ['jwe', 'binary'] as const) {
    const parse = (name: 'dir' | 'pbes' | 'rsa' | 'symmetricBackup' | 'encryptionBackup' | 'wrappedSymmetric' | 'wrappedEncryption' | 'sharedSymmetric' | 'sharedEncryption') => {
      const data = format === 'jwe' ? EncryptedData.fromJWE(artifact[name]) : EncryptedData.fromBinary(new Uint8Array(artifact.binary[name]!));
      check(data.toJWE() === artifact[name], 'exact JWE preservation');
      return data;
    };
    check(await s.decryptText(parse('dir'), await s.unwrapKey(parse('sharedSymmetric'), wrappingKey, { purpose: 'symmetric' })) === message, 'shared symmetric key');
    check(await a.decryptText(parse('rsa'), await s.unwrapKey(parse('sharedEncryption'), wrappingKey, { purpose: 'encryption' })) === message, 'shared encryption key');
    const unwrappedSymmetric = await a.unwrapKey(parse('wrappedSymmetric'), rsa, { purpose: 'symmetric' });
    const unwrappedEncryption = await a.unwrapKey(parse('wrappedEncryption'), rsa, { purpose: 'encryption' });
    check(await s.decryptText(parse('dir'), unwrappedSymmetric) === message, 'wrapped symmetric key');
    check(await a.decryptText(parse('rsa'), unwrappedEncryption) === message, 'wrapped encryption key');
    check(await s.decryptText(parse('dir'), key) === message, 'dir');
    check(await s.decryptTextWithPassword(parse('pbes'), password) === message, 'pbes');
    check(await a.decryptText(parse('rsa'), rsa) === message, 'rsa');
    check(await s.decryptText(parse('dir'), await s.importKeyWithPassword(parse('symmetricBackup'), password)) === message, 'symmetric backup');
    check(await a.decryptText(parse('rsa'), await a.importEncryptionKeyWithPassword(parse('encryptionBackup'), password)) === message, 'RSA backup');
  }
  check(await a.decryptText(await a.encryptText(message, publicKey), rsa) === message, 'public JWK');
}
export async function consume(artifact: Artifact): Promise<void> {
  await consumeEncryption(artifact);
  const signer = await a.importSigningKey(artifact.signingPrivate) as SigningPrivateKey;
  const verifier = await a.importSigningKey(artifact.signingPublic) as SigningPublicKey;
  const recipient = await a.importEncryptionKey(artifact.encryptionPrivate) as EncryptionPrivateKey;
  const sharedSigning = EncryptedData.fromJWE(artifact.sharedSigning);
  for (const data of [sharedSigning, EncryptedData.fromBinary(sharedSigning.toBinary())]) {
    const unwrapped = await s.unwrapKey(data, await s.importKey(artifact.wrappingKey), { purpose: 'signing' });
    check(await a.signText(message, unwrapped) === artifact.signature, 'shared signing key');
  }
  const wrappedSigning = EncryptedData.fromJWE(artifact.wrappedSigning);
  for (const data of [wrappedSigning, EncryptedData.fromBinary(wrappedSigning.toBinary())]) {
    const unwrapped = await a.unwrapKey(data, recipient, { purpose: 'signing' });
    check(await a.signText(message, unwrapped) === artifact.signature, 'wrapped signing key');
  }
  check(await a.verifyText(message, artifact.signature, verifier), 'signature');
  check(await a.signText(message, signer) === artifact.signature, 'private signing JWK');
  check(await a.signText(message, await a.importSigningKeyWithPassword(EncryptedData.fromBinary(EncryptedData.fromJWE(artifact.signingBackup).toBinary()), password)) === artifact.signature, 'signing backup');
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
