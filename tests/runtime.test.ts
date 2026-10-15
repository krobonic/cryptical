import { expect, test } from 'bun:test';
import { chromium, firefox, webkit } from 'playwright';
import type { Browser, Page } from 'playwright';
import type { Artifact, EncryptionArtifact } from './runtime/cases';
import { resolve, sep } from 'node:path';
async function node(request: unknown): Promise<unknown> {
  const process = Bun.spawn(['node', 'tests/runtime/node.mjs'], { stdin: 'pipe', stdout: 'pipe', stderr: 'pipe' });
  process.stdin.write(JSON.stringify(request)); process.stdin.end();
  const [output, error, code] = await Promise.all([new Response(process.stdout).text(), new Response(process.stderr).text(), process.exited]);
  if (code !== 0) throw new Error(error);
  return JSON.parse(output);
}
test.skipIf(process.env.CRYPTICAL_RUNTIME !== '1')('built JavaScript: every Bun/Node/Chromium/Firefox/WebKit producer → every consumer', async () => {
  const build = await Bun.build({ entrypoints: ['tests/runtime/cases.ts'], outdir: 'tests/.generated', target: 'browser', format: 'esm', plugins: [{ name: 'built-library', setup(build) {
    build.onResolve({ filter: /^\.\.\/\.\.\/(index|src\/(symmetric|asymmetric))\.js$/ }, ({ path }) => ({ path: path.replace('../../', '../../dist/'), external: true }));
  } }] });
  expect(build.success).toBe(true);
  const cases = await import('./.generated/cases.js' as string) as typeof import('./runtime/cases');
  const root = process.cwd();
  const server = Bun.serve({ port: 0, hostname: '127.0.0.1', async fetch(request) {
    const path = resolve(root, '.' + new URL(request.url).pathname);
    if (!path.startsWith(root + sep)) return new Response('Forbidden', { status: 403 });
    const file = Bun.file(path);
    return await file.exists() ? new Response(file) : new Response('Not found', { status: 404 });
  } });
  const browsers: Browser[] = [], pages: Page[] = [], signingPages: Page[] = [];
  const unsupported: string[] = [];
  const producers = ['Bun', 'Node'], encryptionProducers = ['Bun', 'Node'];
  const pageNames: string[] = [], signingPageNames: string[] = [];
  async function consumeAll<T>(artifacts: T[], producers: string[], consumer: string, consume: (artifact: T) => Promise<unknown>): Promise<void> {
    for (const [i, artifact] of artifacts.entries()) {
      try { await consume(artifact); }
      catch (error) { throw new Error(`${producers[i]} → ${consumer}: ${String(error)}`, { cause: error }); }
    }
  }
  try {
    await cases.adversarial();
    const artifacts: Artifact[] = [await cases.produce(), await node({ action: 'produce' }) as Artifact];
    const encryptionArtifacts: EncryptionArtifact[] = [...artifacts];
    console.log(`Bun ${Bun.version}, Node ${await node({ action: 'version' })}`);
    for (const engine of [chromium, firefox, webkit]) {
      let browser: Browser;
      try { browser = await engine.launch(); }
      catch (error) {
        unsupported.push(`${engine.name()} launch failed: ${String(error)}`);
        console.log(`${engine.name()}: launch failed; continuing remaining engines`);
        continue;
      }
      browsers.push(browser);
      const page = await browser.newPage(); pages.push(page);
      const name = `${engine.name()} ${browser.version()}`; pageNames.push(name);
      await page.goto(`http://127.0.0.1:${server.port}/tests/runtime/index.html`);
      await page.waitForFunction(() => !!(window as unknown as { cases: unknown }).cases);
      encryptionArtifacts.push(await page.evaluate(() => (window as unknown as { cases: typeof import('./runtime/cases') }).cases.produceEncryption()));
      encryptionProducers.push(name);
      try {
        artifacts.push(await page.evaluate(async () => {
          const c = (window as unknown as { cases: typeof import('./runtime/cases') }).cases;
          await c.adversarial(); return c.produce();
        }));
        signingPages.push(page); signingPageNames.push(name); producers.push(name);
        console.log(`${engine.name()} ${browser.version()}: produced and passed adversarial vectors`);
      } catch (error) {
        // Keep running encryption interchange, but fail the full-support gate below.
        if (!String(error).includes('CryptoUnavailableError')) throw new Error(`${name}: ${String(error)}`, { cause: error });
        unsupported.push(`${engine.name()} ${browser.version()}: ${String(error)}`);
        console.log(unsupported.at(-1));
      }
    }
    await consumeAll(encryptionArtifacts, encryptionProducers, 'Bun encryption', cases.consumeEncryption);
    await consumeAll(encryptionArtifacts, encryptionProducers, 'Node encryption', async artifact => {
      expect(await node({ action: 'consumeEncryption', artifacts: [artifact] })).toBe(true);
    });
    for (const [i, page] of pages.entries()) await consumeAll(encryptionArtifacts, encryptionProducers, pageNames[i]!, artifact => page.evaluate(async artifact => {
      await (window as unknown as { cases: typeof import('./runtime/cases') }).cases.consumeEncryption(artifact);
    }, artifact));
    console.log(`Passed ${encryptionArtifacts.length ** 2} encryption/JWK/backup producer/consumer combinations`);
    await consumeAll(artifacts, producers, 'Bun', cases.consume);
    await consumeAll(artifacts, producers, 'Node', async artifact => {
      expect(await node({ action: 'consume', artifacts: [artifact] })).toBe(true);
    });
    for (const [i, page] of signingPages.entries()) await consumeAll(artifacts, producers, signingPageNames[i]!, artifact => page.evaluate(async artifact => {
      await (window as unknown as { cases: typeof import('./runtime/cases') }).cases.consume(artifact);
    }, artifact));
    console.log(`Passed ${artifacts.length ** 2} producer/consumer combinations`);
    console.log('Node password timing (ms):', await node({ action: 'benchmark' }));
    if (unsupported.length) throw new Error('Full runtime support gate failed:\n' + unsupported.join('\n'));
  } finally {
    await Promise.all(browsers.map(b => b.close())); server.stop(true);
  }
}, 180000);
