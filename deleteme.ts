import { EncryptedData, symmetric } from './index';

// Encrypt
// const key = await symmetric.generateKey();
// const encrypted = await symmetric.encryptText('attack at dawn motherfucker', key);
// await Bun.file('key.json').write(
//   JSON.stringify(await symmetric.exportKey(key)),
// );
// console.log(encrypted.toJWE());

// Decrypt
const key = await symmetric.importKey(JSON.parse(await Bun.file('key.json').text()));
const decrypted = await symmetric.decryptText(EncryptedData.fromJWE('eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..U2NwH0SShySvHKnS.1z0_cTHrSywwWBGa6fEpvp39Tz23z_nUdb7F.d06m95JGyXuNaCjAxr_QCQ'), key);
console.log(decrypted);
