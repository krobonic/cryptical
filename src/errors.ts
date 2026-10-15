/** Base class for all library errors. Native failures are deliberately not exposed. */
export class CrypticalError extends Error {
  constructor(message: string) { super(message); this.name = 'CrypticalError'; }
}
export class InvalidArgumentError extends CrypticalError { override name = 'InvalidArgumentError'; }
export class InvalidKeyError extends CrypticalError { override name = 'InvalidKeyError'; }
export class CryptoUnavailableError extends CrypticalError { override name = 'CryptoUnavailableError'; }
export class EncryptionError extends CrypticalError { override name = 'EncryptionError'; }
export class DecryptionError extends CrypticalError {
  override name = 'DecryptionError';
  constructor() { super('Decryption failed'); }
}
export class SignatureError extends CrypticalError { override name = 'SignatureError'; }
