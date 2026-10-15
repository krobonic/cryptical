import { expect, test, spyOn } from 'bun:test';
import { EncryptedData, symmetric as s, asymmetric as a, DecryptionError, InvalidArgumentError } from '../index';
import { b64, utf8, unb64, text, MAX_BYTES } from '../src/internal/encoding';
import fixture from './fixtures/interop.json';

test('JWE parsing rejects excessive delimiters within the input limit', () => {
  expect(() => EncryptedData.fromJWE('.'.repeat(24 * 1024 * 1024))).toThrow(DecryptionError);
});

test('JWE parsing rejects extra segments after a valid envelope', () => {
  for (const jwe of [fixture.jwe.dir, fixture.jwe.password, fixture.jwe.recipient]) {
    for (const suffix of ['.', '.extra', '..', '.extra.more']) {
      expect(() => EncryptedData.fromJWE(jwe + suffix)).toThrow(DecryptionError);
    }
  }
});

test('JWE parsing preserves and decrypts valid empty ciphertext', async () => {
  const key = await s.generateKey(), input = new Uint8Array();
  const jwe = (await s.encrypt(input, key)).toJWE();
  expect(jwe.split('.')[3]).toBe('');
  const parsed = EncryptedData.fromJWE(jwe);
  expect(parsed.toJWE()).toBe(jwe);
  expect(EncryptedData.fromBinary(parsed.toBinary()).toJWE()).toBe(jwe);
  expect(await s.decrypt(parsed, key)).toEqual(input);
});

test('binary fixtures preserve exact JWE across all suites', async () => {
  for (const jwe of [fixture.jwe.dir, fixture.jwe.password, fixture.jwe.recipient]) {
    const data = EncryptedData.fromJWE(jwe), binary = data.toBinary();
    expect(EncryptedData.fromBinary(binary).toJWE()).toBe(jwe);
    expect(EncryptedData.fromJWE(EncryptedData.fromBinary(binary).toJWE()).toBinary()).toEqual(binary);
  }
  expect(s.EncryptedData).toBe(EncryptedData);
  expect(a.EncryptedData).toBe(EncryptedData);
});

test('version 1 matches independently packed golden bytes', () => {
  const hex = '434b49540100000027000000000000001265794a68624763694f694a6b615849694c434a6c626d4d694f694a424d6a553252304e4e496e3051796074f76dc2aa8b99d40041ba7be5b32493ca437262a85a5fb48a765e2e130c09f5c4799e764191fbcb289dac';
  const binary = Uint8Array.from(hex.match(/../g)!, byte => parseInt(byte, 16));
  expect(EncryptedData.fromJWE(fixture.jwe.dir).toBinary()).toEqual(binary);
  expect(EncryptedData.fromBinary(binary).toJWE()).toBe(fixture.jwe.dir);
});

test('binary output has fixed overhead, arbitrary bytes and empty data round-trip', async () => {
  const key = await s.generateKey();
  for (const input of [new Uint8Array(), Uint8Array.from({ length: 65536 }, (_, i) => i % 256), new Uint8Array(MAX_BYTES)]) {
    const sealed = await s.encrypt(input, key);
    const binary = sealed.toBinary();
    expect(binary.length).toBe(input.length + 17 + sealed.toJWE().split('.')[0]!.length + 12 + 16);
    expect(await s.decrypt(EncryptedData.fromBinary(binary), key)).toEqual(input);
  }
});

test('binary parsing and serialization isolate mutations and respect byte views', async () => {
  const key = await s.generateKey(), sealed = await s.encryptText('immutable', key), expected = sealed.toJWE();
  const binary = sealed.toBinary(), padded = new Uint8Array(binary.length + 8);
  padded.set(binary, 4);
  const parsed = EncryptedData.fromBinary(padded.subarray(4, -4));
  padded.fill(0); binary.fill(0); parsed.toBinary().fill(0);
  expect(sealed.toJWE()).toBe(expected);
  expect(parsed.toJWE()).toBe(expected);
  expect(Object.isFrozen(parsed)).toBe(true);
  expect(await s.decryptText(parsed, key)).toBe('immutable');
  expect(() => EncryptedData.fromJWE(42 as never)).toThrow(InvalidArgumentError);
  expect(() => EncryptedData.fromBinary('bytes' as never)).toThrow(InvalidArgumentError);
  await expect(s.decrypt(Object.create(EncryptedData.prototype), key)).rejects.toBeInstanceOf(InvalidArgumentError);
  expect(() => new (EncryptedData as any)({})).toThrow(InvalidArgumentError);
});

test('binary framing rejects truncation, trailing bytes, versions, magic and hostile lengths', async () => {
  const key = await s.generateKey(), binary = (await s.encryptText('test', key)).toBinary();
  for (let length = 0; length < binary.length; length++) expect(() => EncryptedData.fromBinary(binary.subarray(0, length))).toThrow(DecryptionError);
  expect(() => EncryptedData.fromBinary(new Uint8Array([...binary, 0]))).toThrow(DecryptionError);
  for (const offset of [0, 4, 5, 9, 13]) {
    const bad = binary.slice(); bad[offset] = 255;
    expect(() => EncryptedData.fromBinary(bad)).toThrow(DecryptionError);
  }
  const oversized = new Uint8Array(17 + 5462 + 512 + 12 + MAX_BYTES + 17);
  expect(() => EncryptedData.fromBinary(oversized)).toThrow(DecryptionError);
});

test('binary IV, ciphertext and tag tampering fail authentication', async () => {
  const key = await s.generateKey(), data = await s.encryptText('secret', key), binary = data.toBinary();
  const headerLength = new DataView(binary.buffer).getUint32(5);
  for (const offset of [17 + headerLength, 17 + headerLength + 12, binary.length - 1]) {
    const bad = binary.slice(); bad[offset] = bad[offset]! ^ 1;
    await expect(s.decrypt(EncryptedData.fromBinary(bad), key)).rejects.toBeInstanceOf(DecryptionError);
  }
});

test('binary password metadata is rejected before key derivation', async () => {
  const data = await s.encryptTextWithPassword('test', 'password'), binary = data.toBinary();
  const headerLength = new DataView(binary.buffer).getUint32(5);
  const original = JSON.parse(text(unb64(data.toJWE().split('.')[0]!, 4096)));
  const derive = spyOn(crypto.subtle, 'deriveKey');
  try {
    for (const change of [{ p2c: 1000001 }, { p2s: b64(new Uint8Array(65)) }, { zip: 'DEF' }, { cty: 'other' }]) {
      const header = utf8(b64(utf8(JSON.stringify({ ...original, ...change }))));
      const bad = new Uint8Array(binary.length - headerLength + header.length);
      bad.set(binary.subarray(0, 17)); new DataView(bad.buffer).setUint32(5, header.length);
      bad.set(header, 17); bad.set(binary.subarray(17 + headerLength), 17 + header.length);
      expect(() => EncryptedData.fromBinary(bad)).toThrow(DecryptionError);
    }
    expect(derive).not.toHaveBeenCalled();
  } finally { derive.mockRestore(); }
});

test('protected key backups serialize both ways and retain payload purpose', async () => {
  const key = await s.generateKey(), rsa = await a.generateEncryptionKeyPair(), signer = await a.generateSigningKeyPair();
  const cases = [
    { backup: await s.exportKeyWithPassword(key, 'password'), expected: await s.exportKey(key), restore: async (data: EncryptedData) => s.exportKey(await s.importKeyWithPassword(data, 'password')) },
    { backup: await a.exportKeyWithPassword(rsa.privateKey, 'password'), expected: await a.exportKey(rsa.privateKey), restore: async (data: EncryptedData) => a.exportKey(await a.importEncryptionKeyWithPassword(data, 'password')) },
    { backup: await a.exportKeyWithPassword(signer.privateKey, 'password'), expected: await a.exportKey(signer.privateKey), restore: async (data: EncryptedData) => a.exportKey(await a.importSigningKeyWithPassword(data, 'password')) },
  ];
  for (const { backup, expected, restore } of cases) {
    for (const parsed of [EncryptedData.fromBinary(backup.toBinary()), EncryptedData.fromJWE(backup.toJWE())]) {
      expect(await restore(parsed)).toEqual(expected);
      await expect(s.decryptWithPassword(parsed, 'password')).rejects.toBeInstanceOf(DecryptionError);
    }
  }
});
