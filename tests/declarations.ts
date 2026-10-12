// Compile-only declaration consumer. Package self-references resolve published exports.
import { EncryptedData, asymmetric as a, symmetric as s } from 'cypherkit2';
import * as symmetric from 'cypherkit2/symmetric';
import * as asymmetric from 'cypherkit2/asymmetric';
async function consumer() {
  const parsed = EncryptedData.fromBinary(new Uint8Array());
  const encoded: string = parsed.toJWE();
  const binary: Uint8Array = EncryptedData.fromJWE(encoded).toBinary();
  const fromSymmetric: EncryptedData = symmetric.EncryptedData.fromBinary(binary);
  const fromAsymmetric: EncryptedData = asymmetric.EncryptedData.fromJWE(encoded);
  void fromSymmetric; void fromAsymmetric;
  const key = await symmetric.generateKey(), recipient = await a.generateEncryptionKeyPair(), signer = await asymmetric.generateSigningKeyPair();
  await s.decryptText(await s.encryptText('text', key), key);
  await a.decryptText(await a.encryptText('text', recipient.publicKey), recipient.privateKey);
  await a.verifyText('text', await a.signText('text', signer.privateKey), signer.publicKey);
  const publicKey = await a.importEncryptionKey(await a.exportKey(recipient.publicKey));
  const privateKey = await a.importEncryptionKey(await a.exportKey(recipient.privateKey));
  await a.decryptText(await a.encryptText('text', publicKey), privateKey);
  const dynamic = await a.importEncryptionKey(JSON.parse('{}') as JsonWebKey);
  if (dynamic.type === 'public') await a.encryptText('text', dynamic);
  const wrapped = await asymmetric.wrapKey(key, recipient.publicKey);
  const restored = await a.unwrapKey(wrapped, recipient.privateKey, { purpose: 'symmetric' });
  await s.encryptText('text', restored);
  const encryption = await a.unwrapKey(await a.wrapKey(recipient.privateKey, recipient.publicKey), recipient.privateKey, { purpose: 'encryption' });
  await a.decryptText(await a.encryptText('text', recipient.publicKey), encryption);
  const signing = await asymmetric.unwrapKey(await a.wrapKey(signer.privateKey, recipient.publicKey), recipient.privateKey, { purpose: 'signing' });
  await a.signText('text', signing);
  // @ts-expect-error Wrapped public keys are forbidden.
  await a.wrapKey(recipient.publicKey, recipient.publicKey);
  // @ts-expect-error Recipients must have encryption public keys.
  await a.wrapKey(key, signer.publicKey);
  // @ts-expect-error Explicit purpose is required.
  await a.unwrapKey(wrapped, recipient.privateKey);
  // @ts-expect-error Unsupported purpose.
  await a.unwrapKey(wrapped, recipient.privateKey, { purpose: 'public' });
  // @ts-expect-error Unwrapped symmetric keys cannot sign.
  await a.signText('text', restored);
  // @ts-expect-error Unwrapped signing keys cannot decrypt.
  await a.decrypt(wrapped, signing);
  // @ts-expect-error Decryption requires explicit parsing.
  await s.decrypt(encoded, key);
  // @ts-expect-error Encryption returns an object, not a string.
  const ciphertext: string = await s.encryptText('text', key);
  void ciphertext;
  // @ts-expect-error Signing keys cannot encrypt.
  await a.encryptText('text', signer.publicKey);
  // @ts-expect-error Encryption keys cannot sign.
  await a.signText('text', recipient.privateKey);
  // @ts-expect-error Private keys cannot verify.
  await a.verifyText('text', '', signer.privateKey);
  // @ts-expect-error Public backups are forbidden.
  await a.exportKeyWithPassword(recipient.publicKey, 'password');
}
void consumer;
