import type { JsonWebKey } from 'cryptical';
// Compile-only declaration consumer. Package self-references resolve published exports.
import { EncryptedData, asymmetric as a, symmetric as s } from 'cryptical';
import * as symmetric from 'cryptical/symmetric';
import * as asymmetric from 'cryptical/asymmetric';
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
  // JSON.parse returns any: explicit imports must still infer precise key types.
  const signingPair = await a.importSigningKeyPair(JSON.parse('{}'));
  const signingPublic = await asymmetric.importSigningPublicKey(JSON.parse('{}'));
  const signature = await a.signText('text', signingPair.privateKey);
  await a.verifyText('text', signature, signingPair.publicKey);
  await a.verifyText('text', signature, signingPublic);
  const encryptionPair = await asymmetric.importEncryptionKeyPair(JSON.parse('{}'));
  const encryptionPublic = await a.importEncryptionPublicKey(JSON.parse('{}'));
  await a.decryptText(await a.encryptText('text', encryptionPublic), encryptionPair.privateKey);
  await a.encryptText('text', encryptionPair.publicKey);
  // @ts-expect-error Explicit public imports cannot sign.
  await a.signText('text', signingPublic);
  // @ts-expect-error Explicit public imports cannot decrypt.
  await a.decryptText(await a.encryptText('text', encryptionPublic), encryptionPublic);
  const wrapped = await asymmetric.wrapKey(key, recipient.publicKey);
  const restored = await a.unwrapKey(wrapped, recipient.privateKey, { purpose: 'symmetric' });
  await s.encryptText('text', restored);
  const encryption = await a.unwrapKey(await a.wrapKey(recipient.privateKey, recipient.publicKey), recipient.privateKey, { purpose: 'encryption' });
  await a.decryptText(await a.encryptText('text', recipient.publicKey), encryption);
  const signing = await asymmetric.unwrapKey(await a.wrapKey(signer.privateKey, recipient.publicKey), recipient.privateKey, { purpose: 'signing' });
  await a.signText('text', signing);
  const symmetricWrapped = await symmetric.wrapKey(key, key);
  await s.encryptText('text', await s.unwrapKey(symmetricWrapped, key, { purpose: 'symmetric' }));
  const symmetricEncryption = await s.unwrapKey(await s.wrapKey(recipient.privateKey, key), key, { purpose: 'encryption' });
  await a.decrypt(wrapped, symmetricEncryption);
  const symmetricSigning = await symmetric.unwrapKey(await s.wrapKey(signer.privateKey, key), key, { purpose: 'signing' });
  await a.signText('text', symmetricSigning);
  // @ts-expect-error Public payload keys cannot be wrapped.
  await s.wrapKey(recipient.publicKey, key);
  // @ts-expect-error Wrapping key must be symmetric.
  await s.wrapKey(key, recipient.publicKey);
  // @ts-expect-error An explicit purpose is required.
  await s.unwrapKey(symmetricWrapped, key);
  // @ts-expect-error Unsupported purpose.
  await s.unwrapKey(symmetricWrapped, key, { purpose: 'public' });
  // @ts-expect-error Restored signing keys cannot decrypt.
  await s.decrypt(symmetricWrapped, symmetricSigning);
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

// README key export and password backup example, with intermediate variables.
async function readmeKeyBackup() {
  const recipient = await asymmetric.generateEncryptionKeyPair();
  const password = 'use a randomly generated backup passphrase here';
  const publicJwk = await asymmetric.exportKey(recipient.publicKey);
  const importedPublic = await asymmetric.importEncryptionPublicKey(publicJwk);
  const backup = await asymmetric.exportKeyWithPassword(recipient.privateKey, password);
  const savedBackup = backup.toJWE();
  const recoveredPrivate = await asymmetric.importEncryptionKeyWithPassword(
    asymmetric.EncryptedData.fromJWE(savedBackup), password,
  );
  const encrypted = await asymmetric.encryptText('Recovered', importedPublic);
  console.log(await asymmetric.decryptText(encrypted, recoveredPrivate));
}
void readmeKeyBackup;
