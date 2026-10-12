import { DecryptionError, EncryptionError, InvalidArgumentError } from '../errors.js';
import { b64, unb64, utf8, text, concat, MAX_BYTES } from './encoding.js';
import { cryptoProvider, native, random } from './crypto.js';
export const PBES = 'PBES2-HS512+A256KW';
export type Alg = 'dir' | 'RSA-OAEP-256' | typeof PBES;
export interface Header { alg: Alg; enc: 'A256GCM'; p2s?: string; p2c?: number; cty?: 'jwk+json' }
export interface Envelope { header: Header; protected: string; encryptedKey: Uint8Array<ArrayBuffer>; iv: Uint8Array<ArrayBuffer>; content: Uint8Array<ArrayBuffer> }
export function envelopeArgument(value: string): void {
  if (typeof value !== 'string') throw new InvalidArgumentError('Expected JWE string');
}
export function parse(value: string, alg: Alg, cty?: 'jwk+json'): Envelope {
  if (value.length > 24 * 1024 * 1024) throw new DecryptionError();
  const parts = value.split('.');
  if (parts.length !== 5) throw new DecryptionError();
  const [protectedHeader, wrapped, ivString, ciphertext, tagString] = parts as [string, string, string, string, string];
  const header: Header = JSON.parse(text(unb64(protectedHeader, 4096)));
  if (!header || typeof header !== 'object' || Array.isArray(header) || header.alg !== alg || header.enc !== 'A256GCM' || header.cty !== cty) throw new DecryptionError();
  const allowed = alg === PBES ? ['alg', 'enc', 'p2s', 'p2c', 'cty'] : ['alg', 'enc', 'cty'];
  if (Object.keys(header).some(k => !allowed.includes(k))) throw new DecryptionError();
  if (alg === PBES) {
    if (!Number.isInteger(header.p2c) || header.p2c! < 220000 || header.p2c! > 1000000 || typeof header.p2s !== 'string') throw new DecryptionError();
    const salt = unb64(header.p2s, 64);
    if (salt.length < 16) throw new DecryptionError();
  }
  const encryptedKey = unb64(wrapped, 512);
  if (alg === 'dir' ? encryptedKey.length !== 0 : alg === PBES ? encryptedKey.length !== 40 : ![384, 512].includes(encryptedKey.length)) throw new DecryptionError();
  const iv = unb64(ivString, 12), tag = unb64(tagString, 16);
  if (iv.length !== 12 || tag.length !== 16) throw new DecryptionError();
  return { header, protected: protectedHeader, encryptedKey, iv, content: concat(unb64(ciphertext, cty === 'jwk+json' ? 32768 : MAX_BYTES), tag) };
}
export async function contentKey(usages: KeyUsage[] = ['encrypt']): Promise<CryptoKey> {
  return native(() => cryptoProvider().subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, usages), new EncryptionError('Key generation failed'));
}
export async function seal(data: Uint8Array<ArrayBuffer>, key: CryptoKey, header: Header, wrapped = new Uint8Array(0)): Promise<string> {
  const protectedHeader = b64(utf8(JSON.stringify(header))), iv = random(12);
  const result = new Uint8Array(await native(() => cryptoProvider().subtle.encrypt({ name: 'AES-GCM', iv, additionalData: utf8(protectedHeader), tagLength: 128 }, key, data), new EncryptionError('Encryption failed')));
  return [protectedHeader, b64(wrapped), b64(iv), b64(result.subarray(0, -16)), b64(result.subarray(-16))].join('.');
}
export async function open(envelope: Envelope, key: CryptoKey): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await cryptoProvider().subtle.decrypt({ name: 'AES-GCM', iv: envelope.iv, additionalData: utf8(envelope.protected), tagLength: 128 }, key, envelope.content));
}
