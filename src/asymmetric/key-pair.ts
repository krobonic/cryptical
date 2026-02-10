import { asU8 } from '../helpers.ts';
import { BinaryLike } from '../types';

interface AsymmetricKeyPair {
  publicKey: CryptoKey;
  privateKey?: CryptoKey;
}
interface RawAsymmetricKeyPair {
  publicKey: Uint8Array;
  privateKey?: Uint8Array;
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
        ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'],
      ),
    );
  };

  public static import = async (publicKey: BinaryLike, privateKey?: BinaryLike): Promise<KeyPair> => {
    return new KeyPair({
      publicKey: await crypto.subtle.importKey('spki', publicKey, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt', 'decrypt']),
      privateKey: privateKey ? await crypto.subtle.importKey('pkcs8', privateKey, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt']) : undefined,
    });
  }

  public export = async (): Promise<RawAsymmetricKeyPair> => {
    return {
      publicKey: new Uint8Array(await crypto.subtle.exportKey('spki', this.publicKey)),
      privateKey: this.privateKey ? new Uint8Array(await crypto.subtle.exportKey('pkcs8', this.privateKey)) : undefined,
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
