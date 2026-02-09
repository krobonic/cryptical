import { describe, expect, test } from "bun:test";
import { DataKey, PasswordKey, WrappingKey } from "./key";
import { EncryptedData } from "./encrypted-data";
import { Text } from "../text";

describe("Symmetric API", () => {
  describe("EncryptedData", () => {
    test("should store iv and ciphertext", () => {
      const iv = new Uint8Array([1, 2, 3]);
      const ciphertext = new Uint8Array([4, 5, 6]);
      const data = new EncryptedData(iv, ciphertext);
      expect(data.iv).toBe(iv);
      expect(data.ciphertext).toBe(ciphertext);
    });
  });

  describe("DataKey", () => {
    test("should generate a DataKey", async () => {
      const dataKey = await DataKey.generate();
      expect(dataKey).toBeInstanceOf(DataKey);
      expect(dataKey.key.type).toBe("secret");
      expect(dataKey.key.algorithm.name).toBe("AES-GCM");
    });

    test("should export and import a DataKey", async () => {
      const dataKey = await DataKey.generate();
      const exported = await dataKey.export();
      const imported = await DataKey.import(exported);
      
      expect(imported).toBeInstanceOf(DataKey);
      
      // Verify the imported key works by encrypting and decrypting
      const message = Text.encode("Import test");
      const encrypted = await imported.encrypt(message);
      const decrypted = await imported.decrypt(encrypted);
      expect(Text.decode(decrypted)).toBe("Import test");
    });

    test("should encrypt and decrypt data", async () => {
      const dataKey = await DataKey.generate();
      const message = "Hello, World!";
      const encoded = Text.encode(message);
      
      const encrypted = await dataKey.encrypt(encoded);
      expect(encrypted).toBeInstanceOf(EncryptedData);
      
      const decrypted = await dataKey.decrypt(encrypted);
      expect(Text.decode(decrypted)).toBe(message);
    });

    test("should encrypt and decrypt with additional data", async () => {
      const dataKey = await DataKey.generate();
      const message = Text.encode("Secret Message");
      const ad = Text.encode("Additional Data");
      
      const encrypted = await dataKey.encrypt(message, ad);
      const decrypted = await dataKey.decrypt(encrypted, ad);
      
      expect(Text.decode(decrypted)).toBe("Secret Message");
    });

    test("should fail decryption with wrong additional data", async () => {
      const dataKey = await DataKey.generate();
      const message = Text.encode("Secret Message");
      const ad = Text.encode("Correct AD");
      const wrongAd = Text.encode("Wrong AD");
      
      const encrypted = await dataKey.encrypt(message, ad);
      expect(dataKey.decrypt(encrypted, wrongAd)).rejects.toThrow();
    });

    test("should throw error if key doesn't have required usages", async () => {
      const key = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt"]
      );
      expect(() => new DataKey(key as CryptoKey)).toThrow("Provided key cannot perform both 'decrypt' and 'encrypt'");
    });
  });

  describe("WrappingKey", () => {
    test("should generate a WrappingKey", async () => {
      const wrappingKey = await WrappingKey.generate();
      expect(wrappingKey).toBeInstanceOf(WrappingKey);
      expect(wrappingKey.key.algorithm.name).toBe("AES-KW");
    });

    test("should export and import a WrappingKey", async () => {
      const wrappingKey = await WrappingKey.generate();
      const exported = await wrappingKey.export();
      const imported = await WrappingKey.import(exported);
      
      expect(imported).toBeInstanceOf(WrappingKey);
      const exportedAgain = await imported.export();
      expect(exportedAgain).toEqual(exported);
    });

    test("should wrap and unwrap a DataKey", async () => {
      const wrappingKey = await WrappingKey.generate();
      const dataKey = await DataKey.generate();
      
      const wrapped = await wrappingKey.wrapKey(dataKey);
      const unwrapped = await wrappingKey.unwrapDataKey(wrapped);
      
      expect(unwrapped).toBeInstanceOf(DataKey);
      
      // Verify the unwrapped key works
      const message = Text.encode("Wrapped test");
      const encrypted = await unwrapped.encrypt(message);
      const decrypted = await unwrapped.decrypt(encrypted);
      expect(Text.decode(decrypted)).toBe("Wrapped test");
    });

    test("should wrap and unwrap a WrappingKey", async () => {
      const rootKey = await WrappingKey.generate();
      const childKey = await WrappingKey.generate();
      
      const wrapped = await rootKey.wrapKey(childKey);
      const unwrapped = await rootKey.unwrapWrappingKey(wrapped);
      
      expect(unwrapped).toBeInstanceOf(WrappingKey);
      
      const exportedOriginal = await childKey.export();
      const exportedUnwrapped = await unwrapped.export();
      expect(exportedUnwrapped).toEqual(exportedOriginal);
    });
  });

  describe("PasswordKey", () => {
    test("should import from password", async () => {
      const password = "my-secure-password";
      const passwordKey = await PasswordKey.import(password);
      expect(passwordKey).toBeInstanceOf(PasswordKey);
      expect(passwordKey.key.algorithm.name).toBe("PBKDF2");
    });

    test("should derive DataKey", async () => {
      const passwordKey = await PasswordKey.import("password");
      const { salt, dataKey } = await passwordKey.deriveDataKey();
      
      expect(salt).toBeInstanceOf(Uint8Array);
      expect(dataKey).toBeInstanceOf(DataKey);
      
      // Verify it derives a functional key
      const message = Text.encode("Derive test");
      const encrypted = await dataKey.encrypt(message);
      const decrypted = await dataKey.decrypt(encrypted);
      expect(Text.decode(decrypted)).toBe("Derive test");

      // Verify it derives the same key with the same salt by checking if one can decrypt the other
      const { dataKey: dataKey2 } = await passwordKey.deriveDataKey(salt);
      const encrypted2 = await dataKey2.encrypt(message);
      const decryptedWithOriginal = await dataKey.decrypt(encrypted2);
      expect(Text.decode(decryptedWithOriginal)).toBe("Derive test");
    });

    test("should derive WrappingKey", async () => {
      const passwordKey = await PasswordKey.import("password");
      const { salt, wrappingKey } = await passwordKey.deriveWrappingKey();
      
      expect(salt).toBeInstanceOf(Uint8Array);
      expect(wrappingKey).toBeInstanceOf(WrappingKey);
      
      // Verify it derives a functional wrapping key
      const dataKey = await DataKey.generate();
      const wrapped = await wrappingKey.wrapKey(dataKey);
      const unwrapped = await wrappingKey.unwrapDataKey(wrapped);
      expect(unwrapped).toBeInstanceOf(DataKey);

      // Verify it derives the same key with the same salt by checking if one can unwrap what the other wrapped
      const { wrappingKey: wrappingKey2 } = await passwordKey.deriveWrappingKey(salt);
      const wrapped2 = await wrappingKey2.wrapKey(dataKey);
      const unwrappedWithOriginal = await wrappingKey.unwrapDataKey(wrapped2);
      expect(unwrappedWithOriginal).toBeInstanceOf(DataKey);
    });
  });
});
