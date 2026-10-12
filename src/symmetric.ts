import type { SymmetricKey } from './types.js';
import { DecryptionError } from './errors.js';
import { bytes, utf8, text } from './internal/encoding.js';
import { checkKey, decryptOperation } from './internal/crypto.js';
import { contentKey, envelopeArgument, open, parse, seal } from './internal/jwe.js';
import { passwordOpen, passwordSeal } from './internal/password.js';
import { exportJwk, exportProtected, importJwk, importProtected } from './internal/keys.js';
export type { SymmetricKey } from './types.js';
export async function generateKey(): Promise<SymmetricKey> { return await contentKey(['encrypt', 'decrypt']) as SymmetricKey; }
export async function encrypt(data: Uint8Array, key: SymmetricKey): Promise<string> {
  const copy = bytes(data); checkKey(key, 'symmetric', 'encrypt');
  return seal(copy, key, { alg: 'dir', enc: 'A256GCM' });
}
export async function decrypt(value: string, key: SymmetricKey): Promise<Uint8Array> {
  envelopeArgument(value); checkKey(key, 'symmetric', 'decrypt');
  return decryptOperation(() => open(parse(value, 'dir'), key));
}
export async function encryptText(value: string, key: SymmetricKey): Promise<string> { return encrypt(utf8(value), key); }
export async function decryptText(value: string, key: SymmetricKey): Promise<string> {
  const data = await decrypt(value, key);
  try { return text(data); } catch { throw new DecryptionError(); }
}
export async function encryptWithPassword(data: Uint8Array, password: string): Promise<string> { return passwordSeal(bytes(data), password); }
export async function decryptWithPassword(value: string, password: string): Promise<Uint8Array> { return passwordOpen(value, password); }
export async function encryptTextWithPassword(value: string, password: string): Promise<string> { return passwordSeal(utf8(value), password); }
export async function decryptTextWithPassword(value: string, password: string): Promise<string> {
  const data = await passwordOpen(value, password);
  try { return text(data); } catch { throw new DecryptionError(); }
}
export async function exportKey(key: SymmetricKey): Promise<JsonWebKey> { return exportJwk(key, 'symmetric'); }
export async function importKey(jwk: JsonWebKey): Promise<SymmetricKey> { return await importJwk(jwk, 'symmetric') as SymmetricKey; }
export async function exportKeyWithPassword(key: SymmetricKey, password: string): Promise<string> { return exportProtected(key, password, 'symmetric'); }
export async function importKeyWithPassword(value: string, password: string): Promise<SymmetricKey> { return await importProtected(value, password, 'symmetric') as SymmetricKey; }
