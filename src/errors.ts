/** Base class for all library errors. Native failures are deliberately not exposed. */
export class CipherkitError extends Error {
  constructor(message: string) { super(message); this.name = 'CipherkitError'; }
}
export class InvalidArgumentError extends CipherkitError { override name = 'InvalidArgumentError'; }
export class InvalidKeyError extends CipherkitError { override name = 'InvalidKeyError'; }
export class CryptoUnavailableError extends CipherkitError { override name = 'CryptoUnavailableError'; }
export class EncryptionError extends CipherkitError { override name = 'EncryptionError'; }
export class DecryptionError extends CipherkitError {
  override name = 'DecryptionError';
  constructor() { super('Decryption failed'); }
}
export class SignatureError extends CipherkitError { override name = 'SignatureError'; }
