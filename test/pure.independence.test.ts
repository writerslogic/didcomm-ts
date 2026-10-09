/**
 * The library is an independent DIDComm implementation with zero runtime
 * dependencies: every module reachable from the published entry points may
 * import only `node:` built-ins and never didcomm-rust (WASM). The chat demo
 * (src/chat, not published) is excluded.
 */
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

const IMPORT_RE = /(?:import|export)\s[^'"]*?from\s*['"]([^'"]+)['"]|import\(\s*['"]([^'"]+)['"]\s*\)/g;
const ENTRY_POINTS = ['index', 'core/index', 'routing/index', 'transport/index', 'attestation/index', 'provenance/index'];

function reachableModules(entries: string[]): { files: Set<string>; packages: Set<string> } {
  const files = new Set<string>();
  const packages = new Set<string>();
  const queue = [...entries];
  while (queue.length > 0) {
    const file = queue.pop() as string;
    if (files.has(file)) continue;
    files.add(file);
    for (const match of readFileSync(file, 'utf8').matchAll(IMPORT_RE)) {
      const specifier = match[1] ?? match[2];
      if (specifier.startsWith('.')) queue.push(resolve(dirname(file), specifier.replace(/\.js$/, '.ts')));
      else packages.add(specifier);
    }
  }
  return { files, packages };
}

test('published modules import only node: built-ins and never the chat demo', () => {
  const { files, packages } = reachableModules(ENTRY_POINTS.map((e) => join(process.cwd(), 'src', `${e}.ts`)));
  expect(files.size).toBeGreaterThan(15);
  expect([...files].filter((f) => f.includes('/src/chat/'))).toEqual([]);
  expect([...packages].filter((p) => !p.startsWith('node:'))).toEqual([]);
});

test('package.json declares no runtime dependencies and exports every entry point', () => {
  const pkg = JSON.parse(readFileSync(join(process.cwd(), 'package.json'), 'utf8'));
  expect(pkg.dependencies ?? {}).toEqual({});
  expect(pkg.peerDependencies).toBeUndefined();
  for (const entry of ENTRY_POINTS.slice(1)) {
    expect(pkg.exports[`./${entry.replace('/index', '')}`].import).toBe(`./dist/${entry}.js`);
  }
});
