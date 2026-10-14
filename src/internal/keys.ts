import { EncryptedData } from './jwe.js';
import { CryptoUnavailableError, DecryptionError, InvalidKeyError } from '../errors.js';
import { checkKey, cryptoProvider, native, requireEd25519 } from './crypto.js';
import type { Purpose } from './crypto.js';
import { unb64, utf8, text } from './encoding.js';
import { passwordOpen, passwordSeal } from './password.js';
export const MAX_JWK = 32768;
function validate(value: JsonWebKey, purpose: Purpose): { jwk: JsonWebKey; usages: KeyUsage[] } {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new InvalidKeyError('Expected JWK object');
  const serialized = JSON.stringify(value);
  utf8(serialized, MAX_JWK);
  const jwk: JsonWebKey = JSON.parse(serialized);
  const privateKey = Object.hasOwn(jwk, 'd');
  const usages: KeyUsage[] = purpose === 'symmetric' ? ['encrypt', 'decrypt'] : purpose === 'encryption' ? [privateKey ? 'decrypt' : 'encrypt'] : [privateKey ? 'sign' : 'verify'];
  const alg = purpose === 'symmetric' ? 'A256GCM' : purpose === 'encryption' ? 'RSA-OAEP-256' : 'EdDSA';
  if ((jwk.alg !== undefined && jwk.alg !== alg && !(purpose === 'signing' && jwk.alg === 'Ed25519')) || (jwk.use !== undefined && jwk.use !== (purpose === 'signing' ? 'sig' : 'enc')) || (jwk.ext !== undefined && jwk.ext !== true)) throw new InvalidKeyError('Incompatible JWK metadata');
  if (jwk.key_ops !== undefined && (!Array.isArray(jwk.key_ops) || new Set(jwk.key_ops).size !== jwk.key_ops.length || jwk.key_ops.length !== usages.length || jwk.key_ops.some(v => !usages.includes(v as KeyUsage)))) throw new InvalidKeyError('Incompatible JWK usages');
  const field = (name: keyof JsonWebKey, length?: number) => {
    const v = jwk[name];
    if (typeof v !== 'string') throw new InvalidKeyError('Missing JWK material');
    const decoded = unb64(v, 512);
    if (!decoded.length || (length !== undefined && decoded.length !== length)) throw new InvalidKeyError('Invalid JWK material length');
    return decoded;
  };
  if (purpose === 'symmetric') {
    if (jwk.kty !== 'oct' || privateKey) throw new InvalidKeyError('Expected symmetric JWK');
    field('k', 32);
  } else if (purpose === 'signing') {
    if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') throw new InvalidKeyError('Expected Ed25519 JWK');
    field('x', 32);
    if (privateKey) field('d', 32);
  } else {
    if (jwk.kty !== 'RSA' || jwk.e !== 'AQAB' || jwk.oth !== undefined) throw new InvalidKeyError('Expected two-prime RSA JWK with exponent 65537');
    const n = field('n');
    if (![384, 512].includes(n.length) || n[0]! < 128) throw new InvalidKeyError('RSA modulus must be 3072 or 4096 bits');
    if (privateKey) for (const f of ['d', 'p', 'q', 'dp', 'dq', 'qi'] as const) {
      if (field(f)[0] === 0) throw new InvalidKeyError('Noncanonical RSA integer');
    }
  }
  const material = purpose === 'symmetric' ? ['k'] : purpose === 'signing' ? ['x', ...(privateKey ? ['d'] : [])] : ['n', 'e', ...(privateKey ? ['d', 'p', 'q', 'dp', 'dq', 'qi'] : [])];
  for (const f of ['k', 'x', 'y', 'n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi', 'oth']) {
    if (Object.hasOwn(jwk, f) && !material.includes(f)) throw new InvalidKeyError('Unexpected key material');
  }
  return { jwk, usages };
}
export async function importJwk(value: JsonWebKey, purpose: Purpose): Promise<CryptoKey> {
  cryptoProvider();
  try {
    const { jwk, usages } = validate(value, purpose);
    if (purpose === 'signing') { await requireEd25519(); delete jwk.alg; } // Providers differ on EdDSA versus Ed25519 metadata.
    const algorithm = purpose === 'symmetric' ? { name: 'AES-GCM' } : purpose === 'signing' ? { name: 'Ed25519' } : { name: 'RSA-OAEP', hash: 'SHA-256' };
    const key = await native(() => cryptoProvider().subtle.importKey('jwk', jwk, algorithm, true, usages), new InvalidKeyError('JWK import failed'));
    if (purpose === 'signing' && key.type === 'private') {
      // Some providers silently replace x with the public component derived from d.
      const exported = await native(() => cryptoProvider().subtle.exportKey('jwk', key), new InvalidKeyError('JWK consistency check failed'));
      if (exported.x !== jwk.x) throw new InvalidKeyError('Inconsistent Ed25519 private JWK');
    }
    return key;
  } catch (error) {
    if (error instanceof CryptoUnavailableError) throw error;
    throw new InvalidKeyError('Invalid or incompatible JWK');
  }
}
export async function exportJwk(key: CryptoKey, purpose: Purpose): Promise<JsonWebKey> {
  checkKey(key, purpose);
  if (!key.extractable) throw new InvalidKeyError('Key is not extractable');
  const jwk = await native(() => cryptoProvider().subtle.exportKey('jwk', key), new InvalidKeyError('JWK export failed'));
  if (purpose === 'signing') jwk.alg = 'EdDSA';
  // Every export, including protected payloads, must satisfy the import policy.
  return validate(jwk, purpose).jwk;
}
export async function exportProtectedBytes(key: CryptoKey, purpose: Purpose): Promise<Uint8Array<ArrayBuffer>> {
  checkKey(key, purpose);
  if (purpose !== 'symmetric' && key.type !== 'private') throw new InvalidKeyError('Protected export requires a private key');
  return utf8(JSON.stringify(await exportJwk(key, purpose)), MAX_JWK);
}
export async function importProtectedBytes(data: Uint8Array, purpose: Purpose): Promise<CryptoKey> {
  try {
    if (data.length > MAX_JWK) throw new DecryptionError();
    const key = await importJwk(JSON.parse(text(data)), purpose);
    if (purpose !== 'symmetric' && key.type !== 'private') throw new DecryptionError();
    return key;
  } catch (error) {
    if (error instanceof CryptoUnavailableError) throw error;
    throw new DecryptionError();
  }
}

export async function exportProtected(key: CryptoKey, password: string, purpose: Purpose): Promise<EncryptedData> {
  return passwordSeal(await exportProtectedBytes(key, purpose), password, 'jwk+json');
}
export async function importProtected(value: EncryptedData, password: string, purpose: Purpose): Promise<CryptoKey> {
  return importProtectedBytes(await passwordOpen(value, password, 'jwk+json'), purpose);
}
