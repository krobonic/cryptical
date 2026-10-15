import { CryptoUnavailableError, CipherkitError, DecryptionError, InvalidKeyError } from '../errors.js';
export function cryptoProvider(): Crypto {
  if (!globalThis.crypto?.subtle || !globalThis.crypto.getRandomValues) throw new CryptoUnavailableError('Native Web Crypto requires a supported secure context');
  return globalThis.crypto;
}
export function random(size: number): Uint8Array<ArrayBuffer> { return cryptoProvider().getRandomValues(new Uint8Array(size)); }
export async function native<T>(operation: () => Promise<T>, failure: CipherkitError): Promise<T> {
  try { return await operation(); }
  catch (error) {
    if (error instanceof CipherkitError) throw error;
    if (error instanceof Error && error.name === 'NotSupportedError') throw new CryptoUnavailableError('Required native algorithm unavailable');
    throw failure;
  }
}
export type Purpose = 'symmetric' | 'encryption' | 'signing';
export function checkKey(key: CryptoKey, purpose: Purpose, usage?: KeyUsage): void {
  cryptoProvider();
  if (typeof CryptoKey === 'undefined' || !(key instanceof CryptoKey)) throw new InvalidKeyError('Expected native CryptoKey');
  const a = key.algorithm;
  const valid = purpose === 'symmetric'
    ? a.name === 'AES-GCM' && (a as AesKeyAlgorithm).length === 256 && key.type === 'secret'
    : purpose === 'signing' ? a.name === 'Ed25519' && (key.type === 'public' || key.type === 'private')
    : a.name === 'RSA-OAEP' && [3072, 4096].includes((a as RsaHashedKeyAlgorithm).modulusLength)
      && (a as RsaHashedKeyAlgorithm).hash.name === 'SHA-256'
      && Array.from((a as RsaHashedKeyAlgorithm).publicExponent).join(',') === '1,0,1';
  if (!valid || (usage && !key.usages.includes(usage))) throw new InvalidKeyError('Key purpose or usage mismatch');
}
/** Collapse all untrusted-envelope failures, without masking missing native algorithms. */
export async function decryptOperation<T>(operation: () => Promise<T>): Promise<T> {
  try { return await operation(); }
  catch (error) {
    if (error instanceof CryptoUnavailableError || (error instanceof Error && error.name === 'NotSupportedError')) throw new CryptoUnavailableError('Required native algorithm unavailable');
    throw new DecryptionError();
  }
}

// Known native-provider differences must fail explicitly, never select a fallback.
// RFC 8032 section 7.1, TEST 1. Public test material only.
const signingChecks = new WeakMap<SubtleCrypto, Promise<void>>();
export async function requireEd25519(): Promise<void> {
  const subtle = cryptoProvider().subtle;
  let pending = signingChecks.get(subtle);
  if (!pending) {
    pending = (async () => {
      try {
        const hex = (value: string) => Uint8Array.from(value.match(/../g)!, v => parseInt(v, 16));
        const key = await subtle.importKey('raw', hex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'), 'Ed25519', false, ['verify']);
        const signature = hex('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b');
        if (!await subtle.verify('Ed25519', key, signature, new Uint8Array())) throw new Error();
        signature.set(hex('edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010'), 32);
        if (await subtle.verify('Ed25519', key, signature, new Uint8Array())) throw new Error();
      } catch { throw new CryptoUnavailableError('Native Ed25519 provider fails required signature vectors'); }
    })();
    signingChecks.set(subtle, pending);
  }
  return pending;
}
