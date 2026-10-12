// Next.js renders inline bootstrap scripts into every exported page. This pins each page's inline scripts by hash in a
// <meta> Content-Security-Policy, so the hosting header can stay static while only these exact scripts may run.
import { createHash } from 'node:crypto';
import { readdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../dist/', import.meta.url));
const executable = /^(?:(?:text|application)\/(?:java|ecma)script|module)$/i;

async function* pages(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) yield* pages(path);
    else if (entry.name.endsWith('.html')) yield path;
  }
}

let count = 0;
for await (const file of pages(root)) {
  const source = await readFile(file, 'utf8');
  if (source.includes('http-equiv="Content-Security-Policy"')) throw new Error(`${file} already has a CSP meta tag.`);
  const hashes = new Set();
  for (const [, attributes, body] of source.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
    if (/\bsrc\s*=/i.test(attributes)) continue;
    const type = /\btype\s*=\s*["']?([^"'\s>]+)/i.exec(attributes)?.[1];
    if (type && !executable.test(type)) continue;
    hashes.add(`'sha256-${createHash('sha256').update(body, 'utf8').digest('base64')}'`);
  }
  const meta = `<meta http-equiv="Content-Security-Policy" content="script-src 'self' ${[...hashes].join(' ')}"/>`;
  const charset = source.match(/<meta charSet="utf-8"\/>/i);
  const anchor = charset ?? source.match(/<head[^>]*>/i);
  if (!anchor || anchor.index === undefined) throw new Error(`${file} has no <head>.`);
  const at = anchor.index + anchor[0].length;
  const firstScript = source.search(/<script\b/i);
  if (firstScript !== -1 && firstScript < at) throw new Error(`${file} runs a script before its CSP can apply.`);
  await writeFile(file, source.slice(0, at) + meta + source.slice(at));
  count++;
}
if (!count) throw new Error(`No exported pages found in ${root}.`);
console.log(`Pinned inline scripts in ${count} pages.`);
