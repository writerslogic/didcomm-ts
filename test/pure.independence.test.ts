/**
 * The pure backend's claim to be an independent implementation rests on its
 * module graph never reaching didcomm-rust. Walks every static and dynamic
 * import reachable from src/core/pure/index.ts and fails on `didcomm`.
 */
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

const IMPORT_RE = /(?:import|export)\s[^'"]*?from\s*['"]([^'"]+)['"]|import\(\s*['"]([^'"]+)['"]\s*\)/g;

function reachableModules(entry: string): { files: Set<string>; packages: Set<string> } {
  const files = new Set<string>();
  const packages = new Set<string>();
  const queue = [entry];
  while (queue.length > 0) {
    const file = queue.pop() as string;
    if (files.has(file)) continue;
    files.add(file);
    for (const match of readFileSync(file, 'utf8').matchAll(IMPORT_RE)) {
      const specifier = match[1] ?? match[2];
      if (specifier.startsWith('.')) {
        queue.push(resolve(dirname(file), specifier.replace(/\.js$/, '.ts')));
      } else {
        packages.add(specifier.startsWith('@') ? specifier.split('/').slice(0, 2).join('/') : specifier.split('/')[0]);
      }
    }
  }
  return { files, packages };
}

test('src/core/pure never imports didcomm (WASM)', () => {
  const { files, packages } = reachableModules(join(process.cwd(), 'src/core/pure/index.ts'));
  expect(files.size).toBeGreaterThan(5);
  expect([...files].some((f) => f.endsWith('core/envelope.ts'))).toBe(false);
  expect(packages.has('didcomm')).toBe(false);
  const allowed = ['@noble/ciphers', '@noble/curves', '@noble/hashes', 'cbor-x', 'node:crypto', 'node:fs', 'node:path'];
  expect([...packages].filter((p) => !allowed.includes(p))).toEqual([]);
});
