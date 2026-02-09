import type { BinaryLike } from './types';

export function asU8(data: BinaryLike): Uint8Array {
  return data instanceof ArrayBuffer
    ? new Uint8Array(data)
    : new Uint8Array(data.buffer as ArrayBuffer, data.byteOffset, data.byteLength);
}
