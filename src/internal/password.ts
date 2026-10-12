import { EncryptionError, InvalidArgumentError } from '../errors.js';
import { b64, concat, unb64, utf8 } from './encoding.js';
import { cryptoProvider, decryptOperation, native, random } from './crypto.js';
import { contentKey, envelopeArgument, open, parse, PBES, seal } from './jwe.js';
export function passwordBytes(password: string): Uint8Array<ArrayBuffer> {
  const result = utf8(password, 1024);
  if (!result.length) throw new InvalidArgumentError('Password must contain 1–1024 UTF-8 bytes');
  return result;
}
async function derive(password: Uint8Array<ArrayBuffer>, salt: Uint8Array<ArrayBuffer>, iterations: number, usage: 'wrapKey' | 'unwrapKey'): Promise<CryptoKey> {
  const subtle = cryptoProvider().subtle;
  const material = await subtle.importKey('raw', password, 'PBKDF2', false, ['deriveKey']);
  return subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-512', salt: concat(utf8(PBES), new Uint8Array(1), salt), iterations }, material, { name: 'AES-KW', length: 256 }, false, [usage]);
}
export async function passwordSeal(data: Uint8Array<ArrayBuffer>, password: string, cty?: 'jwk+json'): Promise<string> {
  const secret = passwordBytes(password);
  return native(async () => {
    const salt = random(32), key = await contentKey();
    const wrappingKey = await derive(secret, salt, 220000, 'wrapKey');
    const wrapped = new Uint8Array(await cryptoProvider().subtle.wrapKey('raw', key, wrappingKey, 'AES-KW'));
    return seal(data, key, { alg: PBES, enc: 'A256GCM', p2s: b64(salt), p2c: 220000, ...(cty ? { cty } : {}) }, wrapped);
  }, new EncryptionError('Password encryption failed'));
}
export async function passwordOpen(value: string, password: string, cty?: 'jwk+json'): Promise<Uint8Array<ArrayBuffer>> {
  envelopeArgument(value);
  const secret = passwordBytes(password);
  cryptoProvider();
  return decryptOperation(async () => {
    const e = parse(value, PBES, cty);
    const wrappingKey = await derive(secret, unb64(e.header.p2s!, 64), e.header.p2c!, 'unwrapKey');
    const key = await cryptoProvider().subtle.unwrapKey('raw', e.encryptedKey, wrappingKey, 'AES-KW', 'AES-GCM', false, ['decrypt']);
    return open(e, key);
  });
}
