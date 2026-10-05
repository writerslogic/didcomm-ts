/** @type {import('jest').Config} */
export default {
  preset: "ts-jest/presets/default-esm",
  testEnvironment: "node",
  extensionsToTreatAsEsm: [".ts"],
  moduleNameMapper: {
    "^(\\.{1,2}/.*)\\.js$": "$1",
    // Jest always treats a `.wasm` path as ESM-only and refuses to load it
    // (jest-runtime's `isWasm`), so `didcomm/index.js`'s own relative
    // specifier is redirected to a manual-instantiation shim. Scoped to
    // this exact specifier so other code (e.g. `require.resolve`) can still
    // resolve the real .wasm path. See wasm-transform.cjs.
    "^\\./index_bg\\.wasm$": "<rootDir>/wasm-transform.cjs",
  },
  transform: {
    "^.+\\.ts$": ["ts-jest", { useESM: true }],
    "^.+\\.js$": [
      "babel-jest",
      { presets: [["@babel/preset-env", { targets: { esmodules: false }, modules: "commonjs" }]] },
    ],
  },
  // `didcomm`'s wasm-pack "bundler" target build ships plain ESM
  // import/export syntax in index.js/index_bg.js with no `"type": "module"`
  // marker, so it must go through the .js transform above like our own
  // sources do; everything else in node_modules stays untransformed.
  transformIgnorePatterns: ["/node_modules/(?!didcomm)"],
};
