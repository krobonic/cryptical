import { DecryptionError, EncryptionError, InvalidArgumentError } from '../errors.js';
import { b64, unb64, utf8, text, concat, MAX_BYTES } from './encoding.js';
import { cryptoProvider, native, random } from './crypto.js';
export const PBES = 'PBES2-HS512+A256KW';
export type Alg = 'dir' | 'RSA-OAEP-256' | typeof PBES;
export interface Header { alg: Alg; enc: 'A256GCM'; p2s?: string; p2c?: number; cty?: 'jwk+json' }
export interface Envelope { header: Header; protected: string; encryptedKey: Uint8Array<ArrayBuffer>; iv: Uint8Array<ArrayBuffer>; content: Uint8Array<ArrayBuffer> }
const constructionToken = Symbol('EncryptedData');
const envelopes = new WeakMap<EncryptedData, Envelope>();
let create: (envelope: Envelope) => EncryptedData;
const PREFIX = 17, MAX_HEADER = 5462, MAX_BINARY = PREFIX + MAX_HEADER + 512 + 12 + MAX_BYTES + 16;

/** Immutable encrypted payload. Parsing checks structure, not authenticity. */
export class EncryptedData {
  private constructor(envelope: Envelope, token: symbol) {
    if (token !== constructionToken) throw new InvalidArgumentError('Use EncryptedData parsers');
    envelopes.set(this, envelope);
    Object.freeze(this);
  }
  static { create = envelope => new EncryptedData(envelope, constructionToken); }

  static fromJWE(value: string): EncryptedData {
    if (typeof value !== 'string') throw new InvalidArgumentError('Expected JWE string');
    return malformed(() => {
      if (value.length > 24 * 1024 * 1024) throw new DecryptionError();
      const parts = value.split('.');
      if (parts.length !== 5) throw new DecryptionError();
      const [protectedHeader, wrapped, iv, ciphertext, tag] = parts as [string, string, string, string, string];
      const header = readHeader(protectedHeader);
      const authTag = unb64(tag, 16);
      if (authTag.length !== 16) throw new DecryptionError();
      return create(validate({ header, protected: protectedHeader, encryptedKey: unb64(wrapped, 512), iv: unb64(iv, 12), content: concat(unb64(ciphertext, header.cty === 'jwk+json' ? 32768 : MAX_BYTES), authTag) }));
    });
  }

  static fromBinary(value: Uint8Array): EncryptedData {
    if (!(value instanceof Uint8Array)) throw new InvalidArgumentError('Expected binary envelope');
    return malformed(() => {
      if (value.length < PREFIX || value.length > MAX_BINARY) throw new DecryptionError();
      const input = new Uint8Array(value), view = new DataView(input.buffer);
      if (view.getUint32(0) !== 0x434b4954 || input[4] !== 1) throw new DecryptionError();
      const h = view.getUint32(5), k = view.getUint32(9), c = view.getUint32(13);
      if (!h || h > MAX_HEADER || k > 512 || c > MAX_BYTES || input.length !== PREFIX + h + k + 12 + c + 16) throw new DecryptionError();
      const protectedHeader = text(input.subarray(PREFIX, PREFIX + h));
      const header = readHeader(protectedHeader);
      const offset = PREFIX + h;
      return create(validate({ header, protected: protectedHeader, encryptedKey: input.subarray(offset, offset + k), iv: input.subarray(offset + k, offset + k + 12), content: input.subarray(offset + k + 12) }));
    });
  }

  toJWE(): string {
    const e = envelope(this);
    return [e.protected, b64(e.encryptedKey), b64(e.iv), b64(e.content.subarray(0, -16)), b64(e.content.subarray(-16))].join('.');
  }

  toBinary(): Uint8Array<ArrayBuffer> {
    const e = envelope(this), header = utf8(e.protected);
    const output = new Uint8Array(PREFIX + header.length + e.encryptedKey.length + 12 + e.content.length);
    const view = new DataView(output.buffer);
    view.setUint32(0, 0x434b4954); output[4] = 1;
    view.setUint32(5, header.length); view.setUint32(9, e.encryptedKey.length); view.setUint32(13, e.content.length - 16);
    let offset = PREFIX;
    for (const part of [header, e.encryptedKey, e.iv, e.content]) { output.set(part, offset); offset += part.length; }
    return output;
  }
}
function malformed<T>(operation: () => T): T {
  try { return operation(); } catch { throw new DecryptionError(); }
}
function readHeader(value: string): Header {
  const header: Header = JSON.parse(text(unb64(value, 4096)));
  if (!header || typeof header !== 'object' || Array.isArray(header) || !['dir', 'RSA-OAEP-256', PBES].includes(header.alg) || header.enc !== 'A256GCM' || (header.cty !== undefined && header.cty !== 'jwk+json')) throw new DecryptionError();
  const allowed = header.alg === PBES ? ['alg', 'enc', 'p2s', 'p2c', 'cty'] : ['alg', 'enc', 'cty'];
  if (Object.keys(header).some(k => !allowed.includes(k))) throw new DecryptionError();
  if (header.alg === PBES) {
    if (!Number.isInteger(header.p2c) || header.p2c! < 220000 || header.p2c! > 1000000 || typeof header.p2s !== 'string') throw new DecryptionError();
    if (unb64(header.p2s, 64).length < 16) throw new DecryptionError();
  }
  return header;
}
function validate(e: Envelope): Envelope {
  const { alg, cty } = e.header, k = e.encryptedKey.length;
  if (alg === 'dir' ? k !== 0 : alg === PBES ? k !== 40 : ![384, 512].includes(k)) throw new DecryptionError();
  if (e.iv.length !== 12 || e.content.length < 16 || e.content.length - 16 > (cty === 'jwk+json' ? 32768 : MAX_BYTES)) throw new DecryptionError();
  return e;
}
function envelope(value: EncryptedData): Envelope {
  const result = envelopes.get(value);
  if (!result) throw new InvalidArgumentError('Expected EncryptedData');
  return result;
}
export function envelopeArgument(value: EncryptedData): void { envelope(value); }
export function parse(value: EncryptedData, alg: Alg, cty?: 'jwk+json'): Envelope {
  const result = envelope(value);
  if (result.header.alg !== alg || result.header.cty !== cty) throw new DecryptionError();
  return result;
}
export async function contentKey(usages: KeyUsage[] = ['encrypt']): Promise<CryptoKey> {
  return native(() => cryptoProvider().subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, usages), new EncryptionError('Key generation failed'));
}
export async function seal(data: Uint8Array<ArrayBuffer>, key: CryptoKey, header: Header, wrapped = new Uint8Array(0)): Promise<EncryptedData> {
  const protectedHeader = b64(utf8(JSON.stringify(header))), iv = random(12);
  const result = new Uint8Array(await native(() => cryptoProvider().subtle.encrypt({ name: 'AES-GCM', iv, additionalData: utf8(protectedHeader), tagLength: 128 }, key, data), new EncryptionError('Encryption failed')));
  return create({ header: { ...header }, protected: protectedHeader, encryptedKey: new Uint8Array(wrapped), iv, content: result });
}
export async function open(envelope: Envelope, key: CryptoKey): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await cryptoProvider().subtle.decrypt({ name: 'AES-GCM', iv: envelope.iv, additionalData: utf8(envelope.protected), tagLength: 128 }, key, envelope.content));
}
