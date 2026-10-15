import { InvalidArgumentError } from '../errors.js';
export const MAX_BYTES = 16 * 1024 * 1024;
export function bytes(value: Uint8Array, limit = MAX_BYTES): Uint8Array<ArrayBuffer> {
  if (!(value instanceof Uint8Array) || value.byteLength > limit) throw new InvalidArgumentError('Expected bounded Uint8Array');
  return new Uint8Array(value);
}
export function utf8(value: string, limit = MAX_BYTES): Uint8Array<ArrayBuffer> {
  if (typeof value !== 'string' || value.length > limit) throw new InvalidArgumentError('Expected bounded string');
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = value.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new InvalidArgumentError('Unpaired UTF-16 surrogate');
    } else if (c >= 0xdc00 && c <= 0xdfff) throw new InvalidArgumentError('Unpaired UTF-16 surrogate');
  }
  const result = new TextEncoder().encode(value);
  if (result.length > limit) throw new InvalidArgumentError('UTF-8 input exceeds limit');
  return result;
}
export function text(value: Uint8Array): string {
  try { return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(value); }
  catch { throw new InvalidArgumentError('Invalid UTF-8'); }
}
export function b64(value: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < value.length; i += 8192) binary += String.fromCharCode(...value.subarray(i, i + 8192));
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function unb64(value: string, max: number): Uint8Array<ArrayBuffer> {
  if (typeof value !== 'string' || value.length > Math.ceil(max * 4 / 3) || !/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1)
    throw new InvalidArgumentError('Invalid base64url');
  const binary = atob(value.replace(/-/g, '+').replace(/_/g, '/'));
  const result = Uint8Array.from(binary, c => c.charCodeAt(0));
  if (result.length > max || b64(result) !== value) throw new InvalidArgumentError('Noncanonical base64url');
  return result;
}
export function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const result = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) { result.set(p, offset); offset += p.length; }
  return result;
}
