import { gzipSync } from 'node:zlib';
import { rm } from 'node:fs/promises';
if (!process.argv.includes('--check')) await rm('dist', { recursive: true, force: true });
const result = await Bun.build({ entrypoints: ['./index.ts', './src/symmetric.ts', './src/asymmetric.ts'], outdir: './dist', target: 'browser', format: 'esm', splitting: true, minify: true });
if (!result.success) throw new Error(result.logs.join('\n'));
const combined = await Bun.build({ entrypoints: ['./index.ts'], target: 'browser', format: 'esm', minify: true });
if (!combined.success) throw new Error(combined.logs.join('\n'));
const source = await combined.outputs[0]!.text();
const size = gzipSync(source).length;
console.log(`Combined browser entry: ${size} bytes minified/gzipped (budget 15360)`);
if (size > 15360 || /\b(?:Bun|Buffer|WebAssembly)\b|(?:from|import\s*\()\s*["']node:/.test(source)) throw new Error('Distribution constraints failed');
const pkg = await Bun.file('package.json').json();
if (Object.keys(pkg.dependencies ?? {}).length) throw new Error('Runtime dependencies forbidden');
if (process.argv.includes('--check')) {
  for (const entry of Object.values(pkg.exports) as { import: string; types: string }[]) {
    if (!await Bun.file(entry.types).exists()) throw new Error(`Missing declarations: ${entry.types}`);
    await import(new URL(`../${entry.import}`, import.meta.url).href);
  }
  console.log('Package exports, declarations, runtime dependency and source checks passed');
}
