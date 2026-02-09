import { asU8 } from '../helpers.ts';

interface AsymmetricKeyPair {
  publicKey: CryptoKey;
  privateKey?: CryptoKey;
}

export class KeyPair {
  public publicKey: CryptoKey;
  public privateKey?: CryptoKey;

  constructor(keyPair: AsymmetricKeyPair) {
    this.publicKey = keyPair.publicKey;
    this.privateKey = keyPair.privateKey;
  }

  public static generate = async (): Promise<KeyPair> => {
    return new KeyPair(
      await crypto.subtle.generateKey(
        {
          name: 'RSA-OAEP',
          modulusLength: 4096,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256',
        },
        true,
        ['encrypt', 'decrypt'],
      ),
    );
  };

  public export = async (): Promise<{ publicKey: Uint8Array, privateKey?: Uint8Array }> => {
    return {
      publicKey: new Uint8Array(await crypto.subtle.exportKey('raw', this.publicKey)),
      privateKey: this.privateKey ? new Uint8Array(await crypto.subtle.exportKey('raw', this.privateKey)) : undefined,
    };
  };

  public encrypt = async (
    data: BufferSource,
  ): Promise<Uint8Array> => {
    return asU8(await crypto.subtle.encrypt(
      {
        name: 'RSA-OAEP',
      },
      this.publicKey,
      data as BufferSource,
    ));
  };

  public decrypt= async (
    data: BufferSource,
  ): Promise<Uint8Array> => {
    if (!this.privateKey) throw new Error('Cannot decrypt without private key.')
    return asU8(await crypto.subtle.decrypt(
      {
        name: 'RSA-OAEP',
      },
      this.privateKey,
      data as BufferSource,
    ));
  };
}
