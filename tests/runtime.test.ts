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
test.skipIf(process.env.CYPHERKIT_RUNTIME !== '1')('built JavaScript: every Bun/Node/Chromium/Firefox/WebKit producer → every consumer', async () => {
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
  try {
    await cases.adversarial();
    const artifacts: Artifact[] = [await cases.produce(), await node({ action: 'produce' }) as Artifact];
    const encryptionArtifacts: EncryptionArtifact[] = [...artifacts];
    console.log(`Bun ${Bun.version}, Node ${await node({ action: 'version' })}`);
    for (const engine of [chromium, firefox, webkit]) {
      const browser = await engine.launch(); browsers.push(browser);
      const page = await browser.newPage(); pages.push(page);
      await page.goto(`http://127.0.0.1:${server.port}/tests/runtime/index.html`);
      await page.waitForFunction(() => !!(window as unknown as { cases: unknown }).cases);
      encryptionArtifacts.push(await page.evaluate(() => (window as unknown as { cases: typeof import('./runtime/cases') }).cases.produceEncryption()));
      try {
        artifacts.push(await page.evaluate(async () => {
          const c = (window as unknown as { cases: typeof import('./runtime/cases') }).cases;
          await c.adversarial(); return c.produce();
        }));
        signingPages.push(page);
        console.log(`${engine.name()} ${browser.version()}: produced and passed adversarial vectors`);
      } catch (error) {
        // Keep running encryption interchange, but fail the full-support gate below.
        if (!String(error).includes('CryptoUnavailableError')) throw error;
        unsupported.push(`${engine.name()} ${browser.version()}: ${String(error)}`);
        console.log(unsupported.at(-1));
      }
    }
    for (const artifact of encryptionArtifacts) await cases.consumeEncryption(artifact);
    expect(await node({ action: 'consumeEncryption', artifacts: encryptionArtifacts })).toBe(true);
    for (const page of pages) await page.evaluate(async (artifacts) => {
      for (const artifact of artifacts) await (window as unknown as { cases: typeof import('./runtime/cases') }).cases.consumeEncryption(artifact);
    }, encryptionArtifacts);
    console.log(`Passed ${encryptionArtifacts.length ** 2} encryption/JWK/backup producer/consumer combinations`);
    for (const artifact of artifacts) await cases.consume(artifact);
    expect(await node({ action: 'consume', artifacts })).toBe(true);
    for (const page of signingPages) await page.evaluate(async (artifacts) => {
      for (const artifact of artifacts) await (window as unknown as { cases: typeof import('./runtime/cases') }).cases.consume(artifact);
    }, artifacts);
    console.log(`Passed ${artifacts.length ** 2} producer/consumer combinations`);
    console.log('Node password timing (ms):', await node({ action: 'benchmark' }));
    if (unsupported.length) throw new Error('Full runtime support gate failed:\n' + unsupported.join('\n'));
  } finally {
    await Promise.all(browsers.map(b => b.close())); server.stop(true);
  }
}, 180000);
