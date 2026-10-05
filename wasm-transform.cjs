'use strict';

/**
 * Jest stand-in for `didcomm`'s compiled `index_bg.wasm`.
 *
 * wasm-pack's bundler-target glue imports the wasm module directly
 * (`import * as wasm from "./index_bg.wasm"`) and expects that import to
 * resolve synchronously to the instantiated module's exports — a build-tool
 * convention (webpack/Rollup's WASM-as-ESM integration), not something
 * Node or Jest resolve on their own. Worse, Jest's runtime unconditionally
 * treats any path ending in `.wasm` as ESM-only and refuses to `require()`
 * it at all (see `isWasm` in jest-runtime), regardless of any registered
 * transform.
 *
 * jest.config.js's `moduleNameMapper` redirects every `.wasm` specifier to
 * this file instead, so Jest never touches the real `.wasm` path through
 * its module system. This module locates the actual binary via plain `fs`
 * (bypassing Jest's resolver entirely), discovers the module's own declared
 * imports (wasm-pack always imports its sibling glue file, "./index_bg.js",
 * by relative specifier) to build the WebAssembly import object, and
 * instantiates synchronously. The sibling glue IS `require`d (not read via
 * fs), so it still goes through Jest's own module/transform pipeline.
 */

const fs = require('fs');
const path = require('path');

const wasmPath = path.join(
  path.dirname(require.resolve('didcomm/package.json')),
  'index_bg.wasm'
);

const wasmModule = new WebAssembly.Module(fs.readFileSync(wasmPath));

const importObject = {};
for (const imp of WebAssembly.Module.imports(wasmModule)) {
  if (!(imp.module in importObject)) {
    importObject[imp.module] = require(path.resolve(path.dirname(wasmPath), imp.module));
  }
}

const instance = new WebAssembly.Instance(wasmModule, importObject);

module.exports = instance.exports;
