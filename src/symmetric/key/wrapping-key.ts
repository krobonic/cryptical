import { DataKey } from './data-key';
import type { Key } from '../../';
import { asU8 } from '../../helpers.ts';
import type { BinaryLike } from '../../types.ts';

export class WrappingKey {
  public key: CryptoKey;

  constructor(key: CryptoKey) {
    if (!key.usages.includes('wrapKey') && !key.usages.includes('unwrapKey')) {
      throw new Error(
        "Provided key cannot perform both 'wrapKey' and 'unwrapKey'",
      );
    }
    this.key = key;
  }

  public static generate = async (): Promise<WrappingKey> => {
    return new WrappingKey(
      await crypto.subtle.generateKey({ name: 'AES-KW', length: 256 }, true, [
        'wrapKey',
        'unwrapKey',
      ]),
    );
  };

  public static import = async (buff: BinaryLike): Promise<WrappingKey> => {
    return new WrappingKey(
      await crypto.subtle.importKey(
        'raw',
        buff as BufferSource,
        { name: 'AES-KW', length: 256 },
        true,
        ['wrapKey', 'unwrapKey'],
      ),
    );
  };

  public wrapKey = async (key: Key): Promise<Uint8Array> =>
    asU8(await crypto.subtle.wrapKey('raw', key.key, this.key, 'AES-KW'));

  public export = async (): Promise<Uint8Array> => {
    return asU8(await crypto.subtle.exportKey('raw', this.key));
  };

  public unwrapDataKey = async (wrappedKey: BinaryLike): Promise<DataKey> => {
    return new DataKey(
      await crypto.subtle.unwrapKey(
        'raw',
        wrappedKey as BufferSource,
        this.key,
        'AES-KW',
        'AES-GCM',
        true,
        ['encrypt', 'decrypt'],
      ),
    );
  };

  public unwrapWrappingKey = async (
    wrappedKey: BinaryLike,
  ): Promise<WrappingKey> => {
    return new WrappingKey(
      await crypto.subtle.unwrapKey(
        'raw',
        wrappedKey as BufferSource,
        this.key,
        'AES-KW',
        'AES-KW',
        true,
        ['wrapKey', 'unwrapKey'],
      ),
    );
  };
}
