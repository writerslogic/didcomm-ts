### @writerslogic/didcomm-ts

A second DIDComm v2.x implementation, in TypeScript, built to interoperate with other DIDComm implementations (e.g. chat.wyvrn.app) rather than reuse one.

[![CI](https://img.shields.io/github/actions/workflow/status/writerslogic/didcomm-ts/ci.yml?branch=main&label=CI)](https://github.com/writerslogic/didcomm-ts/actions/workflows/ci.yml) [![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/writerslogic/didcomm-ts/blob/main/package.json)

## Verified interop

The mediation client, pickup client, and forward-routing wrapper have been
run end-to-end — `mediate` → `send` → `pickup` → `ack` — against
[mediator.wyvrn.app](https://mediator.wyvrn.app), an independently-built
production DIDComm v2 mediator. That is a full round trip through someone
else's live crypto and someone else's live DID documents, not a mock.

## Architecture

- **`src/core`** — authcrypt/anoncrypt envelope pack/unpack. A thin wrapper
  over the `didcomm` npm package (WASM bindings over `didcomm-rust`),
  supporting JSON (JWE) and CBOR-encoded JWE envelopes, auto-detected on unpack.
  **Multi-recipient note:** one shared-CEK envelope covers every
  `keyAgreement` key that belongs to a *single* recipient DID Doc (e.g. one
  DID listing a key per device) — `didcomm-rust`'s `pack_encrypted` rejects
  key sets spanning more than one DID's `verificationMethod.controller`. Pack
  separately per DID for genuinely distinct parties.
- **`src/core/pure`** (`@writerslogic/didcomm-ts/pure`) — the same API with
  no WASM: an independent JOSE implementation (ECDH-ES/ECDH-1PU + A256KW,
  A256CBC-HS512/A256GCM/XC20P, EdDSA/ES256/ES256K) over the noble libraries,
  for X25519, P-256, P-384, P-521 and secp256k1 keys. Cross-tested against
  didcomm-rust and didcomm-python; see [INTEROP.md](./INTEROP.md).
- **`src/routing`** — DIDComm forward-routing wrap/unwrap, and
  `selectRoutingPath` for picking the right mediator chain among a DID Doc's
  multiple `DIDCommMessaging` service entries (e.g. one entry per device).
- **`src/transport`** — HTTP (Express) and WebSocket transports.
- **`src/attestation`** — *optional extension.* IETF RATS (RFC 9334) device
  attestation evidence carried as an EAT (RFC 9711) CWT, COSE-signed.
  `eatRecipientAttestation` plugs it into both backends' `attestation`
  option, so every recipient key must present a token bound to that key and a
  fresh verifier challenge before it is added to a multi-recipient envelope.
- **`src/provenance`** — *optional extension.* A minimal C2PA manifest
  *reference* carried through a DIDComm attachment's `data` extension field.
  Does not implement C2PA manifest creation, signing, or validation.
- **`src/chat`** — a CLI chat demo (`send` / `listen` / `serve` / `mediate` /
  `pickup`) wiring the above together for interop testing against other
  DIDComm v2 implementations. Supports `did:key`, `did:web` (resolved over
  HTTPS), `did:peer:2`, and long-form `did:peer:4` peer identities; `send`
  resolves the peer's DID Doc and runs `selectRoutingPath` on it, forward-
  wrapping through any declared mediators before sending as either
  JSON or (`--cbor`) CBOR-encoded JWE. `serve` runs the same DIDComm envelope
  receiver as `listen` behind a minimal web chat UI, with its JSON API
  routes bearer-token-protected (constant-time check) — identity, keys, and
  all pack/unpack crypto stay server-side; the browser only ever sees the
  local DID and the plaintext chat log, never key material.

## Quickstart

```sh
npm install
npm run build
npm run typecheck
npm test
```

See it work end to end in under a minute — two local identities, a real
authcrypt message over real HTTP:

```sh
npm run build
npm run demo
```

Run the chat server locally (serves the web UI and the DIDComm receiver on
the same port):

```sh
npm run build
npm start          # or: node dist/chat/cli.js serve 8080
```

The process prints a bearer token to stderr on startup; the web UI prompts
for it once and keeps it in `sessionStorage`.

## Known limitations

- Local identity (`.didcomm-ts/identity.json`) is plaintext by default; set
  `DIDCOMM_TS_PASSPHRASE` before first run to encrypt it at rest
  (AES-256-GCM, scrypt-derived key) for anything beyond local testing.
- The chat log (`.didcomm-ts/messages.json`) is plaintext even when
  `DIDCOMM_TS_PASSPHRASE` is set — that passphrase covers only
  `identity.json`.
- There is still no DID-network-based endpoint discovery: `send`'s
  `<endpoint-url>` argument is always the literal HTTP destination, with
  routing deciding only the envelope wrapping, not the transport target.
- `--cbor` is incompatible with a mediated peer, since forward-wrapping is
  JSON-only; `listen`/`serve` auto-detect either encoding on receipt.
- On an ephemeral host with no persistent disk (e.g. a free Render
  instance), `.didcomm-ts/` resets on every restart/redeploy, including
  identity — expected for a demo deployment, not a production one.
