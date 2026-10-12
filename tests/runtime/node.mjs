import { symmetric } from 'cypherkit2';
import * as subpath from 'cypherkit2/symmetric';
import * as asymmetric from 'cypherkit2/asymmetric';
if (symmetric.encrypt !== subpath.encrypt || typeof asymmetric.sign !== 'function') throw new Error('Package exports failed');
import { produce, consume, produceEncryption, consumeEncryption, adversarial, benchmark } from '../.generated/cases.js';
let input = '';
for await (const chunk of process.stdin) input += chunk;
const request = JSON.parse(input);
if (request.action === 'produce') { await adversarial(); console.log(JSON.stringify(await produce())); }
else if (request.action === 'consume') { for (const artifact of request.artifacts) await consume(artifact); console.log('true'); }
else if (request.action === 'produceEncryption') console.log(JSON.stringify(await produceEncryption()));
else if (request.action === 'consumeEncryption') { for (const artifact of request.artifacts) await consumeEncryption(artifact); console.log('true'); }
else if (request.action === 'version') console.log(JSON.stringify(process.version));
else if (request.action === 'benchmark') console.log(JSON.stringify(await benchmark()));
else throw new Error('Unknown action');
