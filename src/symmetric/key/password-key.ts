import { Text } from '../../';
import { Random } from '../../random';
import { WrappingKey, DataKey } from './';
import { asU8 } from '../../helpers.ts';
import type { BinaryLike } from '../../types.ts';

export class PasswordKey {
  private iterations: number = 1_000_000;
  public key: CryptoKey;

  constructor(key: CryptoKey) {
    if (!key.usages.includes('deriveKey')) {
      throw new Error("Provided key cannot perform 'deriveKey'");
    }
    this.key = key;
  }

  public static import = async (password: string): Promise<PasswordKey> => {
    return new PasswordKey(
      await crypto.subtle.importKey(
        'raw',
        Text.encode(password) as BufferSource,
        'PBKDF2',
        false,
        ['deriveKey'],
      ),
    );
  };

  public deriveWrappingKey = async (
    salt?: BinaryLike,
  ): Promise<{ salt: Uint8Array, wrappingKey: WrappingKey }> => {
    const saltBytes: Uint8Array = salt ? asU8(salt) : Random.salt();
    return {
      salt: saltBytes,
      wrappingKey: new WrappingKey(
        await crypto.subtle.deriveKey(
          {
            name: 'PBKDF2',
            salt: saltBytes as BufferSource,
            iterations: this.iterations,
            hash: 'SHA-256',
          },
          this.key,
          {name: 'AES-KW', length: 256},
          false,
          ['wrapKey', 'unwrapKey'],
        ),
      ),
    };
  };

  public deriveDataKey = async (
    salt?: BinaryLike,
  ): Promise<{ salt: Uint8Array, dataKey: DataKey}> => {
    const saltBytes: Uint8Array = salt ? asU8(salt) : Random.salt();
    const key = new DataKey(
      await crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: saltBytes as BufferSource,
          iterations: this.iterations,
          hash: 'SHA-256',
        },
        this.key,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt'],
      ),
    );
    return { salt: saltBytes, dataKey: key };
  };
}
