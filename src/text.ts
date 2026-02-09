export class Text {
  public static encode = (text: string): Uint8Array => {
    return new TextEncoder().encode(text);
  };

  public static decode = (encoded: Uint8Array): string => {
    return new TextDecoder().decode(encoded);
  };
}
