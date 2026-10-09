### didcomm-ts

An independent DIDComm v2 implementation in TypeScript with zero runtime dependencies, interop-tested against didcomm-rust, didcomm-python and a live mediator.

[![CI](https://img.shields.io/github/actions/workflow/status/writerslogic/didcomm-ts/ci.yml?branch=main&label=CI)](https://github.com/writerslogic/didcomm-ts/actions/workflows/ci.yml) [![npm](https://img.shields.io/npm/v/didcomm-ts)](https://www.npmjs.com/package/didcomm-ts) [![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/writerslogic/didcomm-ts/blob/main/LICENSE)

- **Independent.** The JOSE layer (ECDH-ES and ECDH-1PU + A256KW, ConcatKDF, A256CBC-HS512 / A256GCM / XC20P, EdDSA / ES256 / ES256K), CBOR codec, DID key handling and HTTP/WebSocket transports are implemented here over `node:crypto`. It does not wrap didcomm-rust.
- **Zero runtime dependencies.** `npm install didcomm-ts` installs one package. A test fails the build if any published module imports anything but `node:` built-ins.
- **Interoperable.** Envelopes round-trip in both directions with didcomm-rust and didcomm-python across X25519, P-256, P-384 and P-521, and the library completes mediate → forward → pickup → ack against an independent production mediator. See [INTEROP.md](./INTEROP.md).
- **Fast.** Higher throughput than didcomm-rust's WASM build in every measured case: 1.2–2.9× on X25519 and 4.9–10.1× on P-256 (see [Performance](#performance)).
- **Attestation-gated multi-recipient packing.** Optionally require each recipient key to present an EAT (RFC 9711) device-attestation token bound to that key and a fresh challenge before it joins a shared envelope.

## Install

```sh
npm install didcomm-ts
```

Requires Node.js 22.4 or later. ESM only.

## Usage

You supply two resolvers: one that returns DID Documents and one that returns your private keys (JWK). They have the same shape as didcomm-rust's, so existing resolvers port directly.

```ts
import { packAuthcrypt, unpack, type DIDDoc, type Secret } from 'didcomm-ts';

const docs = new Map<string, DIDDoc>([[alice.id, alice], [bob.id, bob]]);
const did = { resolve: async (id: string) => docs.get(id) ?? null };
const secretsFor = (owned: Secret[]) => ({
  get_secret: async (id: string) => owned.find((s) => s.id === id) ?? null,
  find_secrets: async (ids: string[]) => ids.filter((id) => owned.some((s) => s.id === id)),
});

// Alice -> Bob, sender-authenticated (ECDH-1PU+A256KW, A256CBC-HS512).
const envelope = await packAuthcrypt(
  {
    id: crypto.randomUUID(),
    typ: 'application/didcomm-plain+json',
    type: 'https://didcomm.org/basicmessage/2.0/message',
    from: alice.id,
    to: [bob.id],
    body: { content: 'hello' },
  },
  [bob.id],
  alice.id,
  { did, secrets: secretsFor(aliceSecrets) },
);

const { message, senderKey, recipientKey } = await unpack(envelope, { did, secrets: secretsFor(bobSecrets) });
```

The same options also cover:

- `packAnoncrypt(message, to, options)`: no sender identity. `anoncryptEnc` selects A256CBC-HS512 (default), A256GCM or XC20P.
- `signBy: did`: an inner JWS for non-repudiation. `packSigned` / `unpackSigned` handle signed-only messages.
- `encoding: 'cbor'`: a CBOR-encoded envelope. `unpack` detects JSON or CBOR automatically.
- `attestation`: the multi-recipient trust gate (see `eatRecipientAttestation` in `didcomm-ts/attestation`).

`unpack` also unwraps anoncrypt around authcrypt (protected sender) and a JWS inside a JWE, and checks that the plaintext `from` / `to` match the keys that actually encrypted and signed it.

### Entry points

Import only what you use. Every entry point is dependency-free and side-effect-free.

| Import | Contents |
| --- | --- |
| `didcomm-ts` | Envelope API (`packAuthcrypt`, `packAnoncrypt`, `packSigned`, `unpack`, `unpackSigned`, `anoncryptProvider`, resolver and message types), plus `routing`, `transport`, `attestation` and `provenance` namespaces |
| `didcomm-ts/core` | Envelope API only |
| `didcomm-ts/routing` | `routing/2.0/forward` wrapping (`wrapInForward`, `wrapForwardChain`) and `selectRoutingPath` over a DID Doc's `DIDCommMessaging` services |
| `didcomm-ts/transport` | `listenHttp` / `createHttpHandler` / `sendHttp` (`node:http`) and `listenWebSocket` / `connectWebSocket` (RFC 6455 server, built-in client) |
| `didcomm-ts/attestation` | EAT tokens (`buildEatToken`, `verifyEatToken`) and `eatRecipientAttestation` for the packing gate |
| `didcomm-ts/provenance` | A C2PA manifest reference carried in an attachment |

To forward through a mediator, wrap the packed envelope with `wrapForwardChain(envelope, mediators, recipientDid, anoncryptProvider({ did, secrets }))`.

## Interoperability

| Counterparty | Coverage | Result |
| --- | --- | --- |
| didcomm-rust (`didcomm` 0.4.1, WASM) | authcrypt, anoncrypt (3 content ciphers), signed, CBOR, multi-recipient; X25519 and P-256; both directions; its published test vectors | 33/33 + 8/8 vectors |
| didcomm-python 0.3.2 | authcrypt, anoncrypt (3 content ciphers), signed, protected sender; X25519, P-256, P-384, P-521; both directions | 22/22 |
| mediator.wyvrn.app (live) | Coordinate Mediation, forward, Pickup 3.0, ack | 3/3 recorded runs |
| aviarytech/didcomm 0.1.35 | anoncrypt X25519 | not interoperable: it predates the final DIDComm v2 JWE format, and didcomm-rust rejects it the same way |

Known-answer tests cover RFC 3394, RFC 7518 App. B.3, draft-irtf-cfrg-xchacha-03, the ECDH-1PU draft's Appendix B and RFC 8949. Details, logs and reproduction commands are in [INTEROP.md](./INTEROP.md).

## Performance

![Throughput chart: didcomm-ts vs didcomm-rust (WASM)](https://raw.githubusercontent.com/writerslogic/didcomm-ts/main/docs/images/benchmark.svg)

Median of 15 interleaved 250 ms windows per operation, 1 KiB message, same keys, DID Docs and content cipher (XC20P for anoncrypt) for both libraries. "Reused keys" resolvers return the same objects on every call. "Fresh keys" resolvers return new copies of every document and secret per lookup, as a database-backed resolver would, so no parsed key can be reused. Absolute numbers drift with machine load; the ratios held across both runs ([run 1](https://github.com/writerslogic/didcomm-ts/blob/main/docs/benchmarks/2026-10-09-apple-m4-run1.json), [run 2](https://github.com/writerslogic/didcomm-ts/blob/main/docs/benchmarks/2026-10-09-apple-m4-run2.json)):

| | Reused keys | Fresh keys |
| --- | --- | --- |
| X25519 | 1.7–2.9× | 1.2–1.6× |
| P-256 | 6.4–10.1× | 4.9–7.3× |

Reproduce with `npm run build && npm run bench`.

What this does and doesn't show:

- The comparison is against didcomm-rust's WASM build, which is how JavaScript applications use it. Native Rust was not measured and should be faster.
- didcomm-ts runs elliptic-curve and AEAD work in OpenSSL through `node:crypto`. When a resolver hands back the same key objects, it also reuses their parsed form and native handles (held in WeakMaps, so nothing outlives the caller's objects).

## Chat demo

`src/chat` is a CLI and web chat app built on the library, used for live interop testing. It lives in the repository and is not part of the npm package.

| Alice | Bob |
| --- | --- |
| ![Alice's chat view](https://raw.githubusercontent.com/writerslogic/didcomm-ts/main/docs/images/chat-alice.png) | ![Bob's chat view](https://raw.githubusercontent.com/writerslogic/didcomm-ts/main/docs/images/chat-bob.png) |

```sh
npm install && npm run build
npm run demo                 # two local identities, one authcrypted message over HTTP
npm start                    # web UI + DIDComm receiver; prints an API token to stderr
node dist/chat/cli.js mediate did:web:mediator.wyvrn.app
node dist/chat/cli.js pickup did:web:mediator.wyvrn.app
```

The demo supports `did:key`, `did:web`, `did:peer:2` and long-form `did:peer:4` identities. Keys and all crypto stay server-side; the browser sees only the local DID and the plaintext chat log. The local identity (`.didcomm-ts/identity.json`) is plaintext unless `DIDCOMM_TS_PASSPHRASE` is set before first run. The screenshots come from `node scripts/screenshots.mjs`.

## Development

```sh
npm test                      # unit, vector, interop (didcomm-rust, didcomm-python via uv) and transport tests
npm run interop:live          # mediate -> send -> pickup -> ack against mediator.wyvrn.app
npm run interop:aviary        # aviarytech probe
npm run bench                 # throughput vs didcomm-rust (WASM)
```

didcomm-rust and didcomm-python are development dependencies only: they are the counterparties for the interop tests.

## License

Apache-2.0
