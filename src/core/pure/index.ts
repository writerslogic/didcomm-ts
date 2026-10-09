// Pure-TypeScript DIDComm v2 backend (no didcomm-rust/WASM). Published as the
// `@writerslogic/didcomm-ts/pure` subpath so importing it never loads WASM.
export * from './envelope.js';
export * from '../types.js';
export { detectEnvelopeEncoding } from '../encoding.js';
export type { ContentEnc } from './content.js';
