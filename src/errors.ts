/** Base class for all library errors. Native failures are deliberately not exposed. */
export class CypherkitError extends Error {
  constructor(message: string) { super(message); this.name = 'CypherkitError'; }
}
export class InvalidArgumentError extends CypherkitError { override name = 'InvalidArgumentError'; }
export class InvalidKeyError extends CypherkitError { override name = 'InvalidKeyError'; }
export class CryptoUnavailableError extends CypherkitError { override name = 'CryptoUnavailableError'; }
export class EncryptionError extends CypherkitError { override name = 'EncryptionError'; }
export class DecryptionError extends CypherkitError {
  override name = 'DecryptionError';
  constructor() { super('Decryption failed'); }
}
export class SignatureError extends CypherkitError { override name = 'SignatureError'; }
