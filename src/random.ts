export class Random {
  public static saltLengthBytes: number = 32;
  public static ivLengthBytes: number = 12;

  /**
   * Generates cryptographically secure random bytes
   */
  public static bytes = (lengthBytes: number): Uint8Array =>
    crypto.getRandomValues<Uint8Array>(new Uint8Array(lengthBytes));

  /**
   * Generate a new initialization vector (IV)
   */
  public static iv = (): Uint8Array => this.bytes(this.ivLengthBytes);

  /**
   * Generate a new salt
   */
  public static salt = (): Uint8Array => this.bytes(this.saltLengthBytes);
}
