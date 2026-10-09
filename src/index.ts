// Package entry: the envelope API at the top level, other modules as
// namespaces (each also importable on its own subpath, e.g. didcomm-ts/routing)
// so same-named members across modules never collide.
export * from "./core/index.js";
export * as routing from "./routing/index.js";
export * as transport from "./transport/index.js";
export * as attestation from "./attestation/index.js";
export * as provenance from "./provenance/index.js";
