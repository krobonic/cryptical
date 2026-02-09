import { Symmetric } from './';
export type BinaryLike = ArrayBuffer | ArrayBufferView;

export type Key =
  | Symmetric.DataKey
  | Symmetric.WrappingKey
  | Symmetric.PasswordKey;
