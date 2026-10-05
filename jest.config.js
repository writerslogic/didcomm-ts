// Known limitation: test/core.envelope.test.ts fails under Jest — the
// installed `didcomm@0.4.1` package ships only a wasm-pack "bundler" target
// (`import * as wasm from "./index_bg.wasm"`), which Jest's module loader
// cannot resolve (no WASM-ESM support), independent of this config. The
// pack/unpack logic itself was verified correct via plain Node execution
// (see that test file's header comment); re-check once `didcomm` ships a
// Node-target build or Jest gains WASM module support.
/** @type {import('jest').Config} */
export default {
  preset: "ts-jest/presets/default-esm",
  testEnvironment: "node",
  extensionsToTreatAsEsm: [".ts"],
  moduleNameMapper: {
    "^(\\.{1,2}/.*)\\.js$": "$1",
  },
  transform: {
    "^.+\\.ts$": ["ts-jest", { useESM: true }],
  },
};
