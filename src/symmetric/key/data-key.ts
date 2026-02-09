import { EncryptedData } from '../encrypted-data.ts';
import { Random } from '../../random.ts';
import { asU8 } from '../../helpers.ts';
import type { BinaryLike } from '../../types.ts';

export class DataKey {
  public key: CryptoKey;
  public tagLength: number = 128;

  constructor(key: CryptoKey) {
    if (!key.usages.includes('encrypt') || !key.usages.includes('decrypt')) {
      throw new Error(
        "Provided key cannot perform both 'decrypt' and 'encrypt'",
      );
    }
    this.key = key;
  }

  public static generate = async (): Promise<DataKey> => {
    return new DataKey(
      await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
        'encrypt',
        'decrypt',
      ]),
    );
  };

  public static import = async (data: BinaryLike): Promise<DataKey> => {
    return new DataKey(
      await crypto.subtle.importKey(
        'raw',
        data as BufferSource,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt'],
      ),
    );
  };

  public export = async (): Promise<Uint8Array> => {
    return new Uint8Array(await crypto.subtle.exportKey('raw', this.key));
  };

  public encrypt = async (
    data: BinaryLike,
    additionalData?: BinaryLike,
  ): Promise<EncryptedData> => {
    const iv = Random.iv();
    const encrypted = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv as BufferSource,
        additionalData: additionalData as BufferSource | undefined,
        tagLength: this.tagLength,
      },
      this.key,
      data as BufferSource,
    );
    return new EncryptedData(iv, asU8(encrypted));
  };

  public decrypt = async (
    data: EncryptedData,
    additionalData?: BinaryLike,
  ): Promise<Uint8Array> => {
    return asU8(await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: data.iv as BufferSource,
        additionalData: additionalData as BufferSource | undefined,
        tagLength: this.tagLength,
      },
      this.key,
      data.ciphertext as BufferSource,
    ));
  };
}
