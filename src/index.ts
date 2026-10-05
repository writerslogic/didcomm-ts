// Top-level package entry: re-exports each module under its own namespace
// so that sibling modules exporting same-named members never collide.
export * as core from "./core/index.js";
export * as routing from "./routing/index.js";
export * as transport from "./transport/index.js";
export * as attestation from "./attestation/index.js";
export * as provenance from "./provenance/index.js";
