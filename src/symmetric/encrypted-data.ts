export class EncryptedData {
  public iv: Uint8Array;
  public ciphertext: Uint8Array;

  constructor(iv: Uint8Array, encrypted: Uint8Array) {
    this.iv = iv;
    this.ciphertext = encrypted;
  }
}
