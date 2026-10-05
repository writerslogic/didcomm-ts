# @writerslogic/didcomm-ts

A second DIDComm v2.x implementation, in TypeScript, built to interoperate with
other DIDComm implementations (e.g. chat.wyvrn.app) rather than reuse one.

## Architecture

- `src/core` — authcrypt/anoncrypt envelope pack/unpack. A thin wrapper over
  the `didcomm` npm package (WASM bindings over `didcomm-rust`), supporting
  JSON (JWE) and CBOR (COSE) encoding, auto-detected on unpack.
  **Multi-recipient note:** one shared-CEK envelope covers every
  `keyAgreement` key that belongs to a *single* recipient DID Doc (e.g. one
  DID listing a key per device) — `didcomm-rust`'s `pack_encrypted` rejects
  key sets spanning more than one DID's `verificationMethod.controller`.
  Pack separately per DID for genuinely distinct parties.
- `src/routing` — DIDComm forward-routing wrap/unwrap, and
  `selectRoutingPath` for picking the right mediator chain among a DID Doc's
  multiple `DIDCommMessaging` service entries (e.g. one entry per device).
- `src/transport` — HTTP (Express) and WebSocket transports.
- `src/attestation` — **optional extension.** IETF RATS (RFC 9334) device
  attestation evidence carried as an EAT (RFC 9711) CWT, COSE-signed. Not
  wired into `src/core`; intended future integration point is gating
  whether a primary device trusts a new device's key before adding it to a
  multi-recipient authcrypt envelope.
- `src/provenance` — **optional extension.** A minimal C2PA manifest
  *reference* carried through a DIDComm attachment's `data` extension
  field. Does not implement C2PA manifest creation/signing/validation.
- `src/chat` — a minimal CLI chat demo (`send`/`listen`) wiring the above
  together, for interop testing against other DIDComm v2 implementations.

## Status

Scaffolded modules with unit tests; typecheck clean. One test suite
(`test/core.envelope.test.ts`) does not run under Jest — see the comment at
the top of `jest.config.js` for why (an upstream `didcomm` package packaging
constraint, not a logic defect) — its pack/unpack logic was verified
correct via direct Node execution instead.

## Development

```sh
npm install
npm run typecheck
npm test
```
