<img src="https://raw.githubusercontent.com/writerslogic/didcomm-ts/main/docs/images/logo.png" alt="didcomm-ts logo" width="160">

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

The API follows didcomm-rust's flow:

- **Sender:** build a plaintext message object, then turn it into a DIDComm message with `packAuthcrypt`, `packAnoncrypt` or `packSigned`.
- **Receiver:** call `unpack` (or `unpackSigned` for a signed-only message). It decrypts, verifies any signature, checks the sender and recipient against the plaintext `from` / `to`, and returns the plaintext message.

### Resolvers

You supply two resolvers: one that returns DID Documents and one that returns your private keys as JWKs. They have the same shape as didcomm-rust's `DIDResolver` / `SecretsResolver`, so existing resolvers port directly.

```ts
import { packAuthcrypt, unpack, type DIDDoc, type Secret } from 'didcomm-ts';

const docs = new Map<string, DIDDoc>([[alice.id, alice], [bob.id, bob], [mediator.id, mediator]]);
const did = { resolve: async (id: string) => docs.get(id) ?? null };
const secretsFor = (owned: Secret[]) => ({
  get_secret: async (id: string) => owned.find((s) => s.id === id) ?? null,
  find_secrets: async (ids: string[]) => ids.filter((id) => owned.some((s) => s.id === id)),
});
```

The examples below assume each party's DID Doc lists an X25519 key under `keyAgreement` (`#key-x25519-1`) and an Ed25519 key under `authentication` (`#key-ed25519-1`), and that `message` is a plaintext message such as:

```ts
const message = {
  id: crypto.randomUUID(),
  typ: 'application/didcomm-plain+json',
  type: 'https://didcomm.org/basicmessage/2.0/message',
  from: alice.id,
  to: [bob.id],
  body: { content: 'hello' },
};
```

### 1. Encrypted message, sender authenticated (authcrypt)

Hides the content from everyone but the recipients, proves the sender to those recipients only, and protects integrity. Uses ECDH-1PU+A256KW with A256CBC-HS512.

```ts
const envelope = await packAuthcrypt(message, [bob.id], alice.id, { did, secrets: secretsFor(aliceSecrets) });
const { message: received, senderKey, recipientKey } = await unpack(envelope, { did, secrets: secretsFor(bobSecrets) });
// senderKey === 'did:example:alice#key-x25519-1', recipientKey === 'did:example:bob#key-x25519-1'
```

Add `signBy` to also sign the plaintext, so the sender can be proven to third parties (non-repudiation):

```ts
const envelope = await packAuthcrypt(message, [bob.id], alice.id, {
  did,
  secrets: secretsFor(aliceSecrets),
  signBy: alice.id,
});
const { signedBy } = await unpack(envelope, { did, secrets: secretsFor(bobSecrets) });
// signedBy === 'did:example:alice#key-ed25519-1'
```

### 2. Encrypted message, anonymous sender (anoncrypt)

Confidentiality and integrity without revealing the sender (the plaintext must not carry `from`). Uses ECDH-ES+A256KW; `anoncryptEnc` picks A256CBC-HS512 (default), A256GCM or XC20P.

```ts
const { from, ...anonymous } = message;
const envelope = await packAnoncrypt(anonymous, [bob.id], { did, secrets: secretsFor([]), anoncryptEnc: 'XC20P' });
const { senderKey } = await unpack(envelope, { did, secrets: secretsFor(bobSecrets) });
// senderKey === null
```

### 3. Signed, unencrypted message

For when the origin must be provable to third parties, or the recipient isn't known in advance. The content is readable by anyone who receives it.

```ts
const jws = await packSigned(message, alice.id, { did, secrets: secretsFor(aliceSecrets) });
const { message: verified, signedBy } = await unpackSigned(jws, { did, secrets: secretsFor([]) });
```

### 4. Through a mediator

Forward wrapping is explicit: pack for the final recipient, then wrap the envelope once per mediator (`routing/2.0/forward`, anoncrypted to the mediator).

```ts
import { anoncryptProvider, routing } from 'didcomm-ts';

const forwarded = await routing.wrapForwardChain(
  JSON.parse(envelope as string),
  ['did:example:mediator#key-x25519-1'],
  bob.id,
  anoncryptProvider({ did, secrets: secretsFor([]) }),
);
// POST JSON.stringify(forwarded) to the mediator's endpoint.
```

### 5. DID rotation (`from_prior`)

When Alice rotates to a new DID, her first message from the new DID can carry a `from_prior` JWT signed by a key of the old DID. `unpack` verifies it and reports the rotation.

```ts
import { packFromPrior } from 'didcomm-ts';

const { jwt } = await packFromPrior(
  { iss: oldAlice.id, sub: alice.id, iat: Math.floor(Date.now() / 1000) },
  null, // or a specific authentication key ID of the old DID
  { did, secrets: secretsFor(oldAliceSecrets) },
);
const envelope = await packAuthcrypt({ ...message, from_prior: jwt }, [bob.id], alice.id, {
  did,
  secrets: secretsFor(aliceSecrets),
});
const { fromPrior, fromPriorIssuerKid } = await unpack(envelope, { did, secrets: secretsFor(bobSecrets) });
// fromPrior.iss === oldAlice.id, fromPrior.sub === alice.id
```

`unpack` requires `sub` to equal the message's `from`, `iss` to be the DID of the signing key, and enforces `exp` / `nbf`.

### 6. Plaintext message

No envelope at all: no confidentiality, integrity or sender authentication.

```ts
import { packPlaintext, unpackPlaintext } from 'didcomm-ts';

const json = packPlaintext(message);
const { message: parsed } = await unpackPlaintext(json, { did });
```

`unpack` and `unpackSigned` refuse plaintext, and `unpackPlaintext` refuses envelopes, so a receiver can't mistake one for the other.

Other options on every pack call:

- `encoding: 'cbor'`: a CBOR-encoded envelope. `unpack` detects JSON or CBOR automatically.
- `attestation`: the multi-recipient trust gate (see `eatRecipientAttestation` in `didcomm-ts/attestation`).

`unpack` also unwraps anoncrypt around authcrypt (protected sender). These examples run as tests in [`test/readme.example.test.ts`](https://github.com/writerslogic/didcomm-ts/blob/main/test/readme.example.test.ts).

### Entry points

Import only what you use. Every entry point is dependency-free and side-effect-free.

| Import | Contents |
| --- | --- |
| `didcomm-ts` | Envelope API (`packAuthcrypt`, `packAnoncrypt`, `packSigned`, `packPlaintext`, `unpack`, `unpackSigned`, `unpackPlaintext`, `packFromPrior`, `unpackFromPrior`, `anoncryptProvider`, resolver and message types), plus `routing`, `transport`, `attestation` and `provenance` namespaces |
| `didcomm-ts/core` | Envelope API only |
| `didcomm-ts/routing` | `routing/2.0/forward` wrapping (`wrapInForward`, `wrapForwardChain`) and `selectRoutingPath` over a DID Doc's `DIDCommMessaging` services |
| `didcomm-ts/transport` | `listenHttp` / `createHttpHandler` / `sendHttp` (`node:http`) and `listenWebSocket` / `connectWebSocket` (RFC 6455 server, built-in client) |
| `didcomm-ts/attestation` | EAT tokens (`buildEatToken`, `verifyEatToken`) and `eatRecipientAttestation` for the packing gate |
| `didcomm-ts/provenance` | A C2PA manifest reference carried in an attachment |

To forward through a mediator, wrap the packed envelope with `wrapForwardChain(envelope, mediators, recipientDid, anoncryptProvider({ did, secrets }))`.

## Supported algorithms

| | Curves | Algorithms |
| --- | --- | --- |
| Key agreement | X25519, P-256, P-384, P-521, secp256k1 | ECDH-1PU+A256KW (authcrypt), ECDH-ES+A256KW (anoncrypt) |
| Content encryption | | A256CBC-HS512 (authcrypt and anoncrypt; the only option for authcrypt), A256GCM and XC20P (anoncrypt only) |
| Signing | Ed25519, P-256, secp256k1 | EdDSA, ES256, ES256K |

Ed25519 keys listed under `keyAgreement` are converted to X25519 (RFC 7748). didcomm-rust encrypts only to X25519 and P-256; P-384 and P-521 are cross-tested against didcomm-python; secp256k1 key agreement has no external counterparty tested.

## Assumptions and limitations

- Your application implements the DID and secrets resolvers. Resolving DID methods (`did:web`, `did:peer`, ...) is outside the library; the chat demo in `src/chat` has examples.
- Key material:
  - Public keys: `publicKeyJwk`, or `publicKeyMultibase` for X25519 and Ed25519 keys. `publicKeyBase58` is not supported.
  - Secrets: `privateKeyJwk` only. Each secret's `id` must equal the key ID of the matching verification method.
  - Key IDs should be absolute DID URLs (`did:example:alice#key-1`). Verification methods that live in another DID Document are not supported.
- One envelope can be shared by several keys of a **single** recipient DID (e.g. one key per device). Distinct recipient DIDs need one pack call each, as with didcomm-rust.
- Forward wrapping is not automatic: use `routing.wrapForwardChain` (above). Passing `forward: true` throws.
- `from_prior` verification requires `iss` to be the DID of the signing key and enforces `exp` / `nbf` (`unpackFromPrior(jwt, did, null)` skips the time checks, e.g. for archived messages).
- base64url values must be canonical (unused trailing bits zero), as didcomm-rust requires; other encodings are rejected.
- Node.js only: the library is built on `node:crypto` and `node:http`.

## Interoperability

| Counterparty | Coverage | Result |
| --- | --- | --- |
| didcomm-rust (`didcomm` 0.4.1, WASM) | authcrypt, anoncrypt (3 content ciphers), signed, CBOR, multi-recipient, `from_prior`, plaintext; X25519 and P-256; both directions; its published test vectors | 36/36 cross-tests, 11/11 vectors |
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

## Contributing

Pull requests are welcome. Before opening one:

- `npm run typecheck` and `npm run build` succeed.
- `npm test` passes, including the didcomm-rust and didcomm-python interop suites (install [uv](https://docs.astral.sh/uv/) for the Python counterparty; CI sets `DIDCOMM_TS_REQUIRE_INTEROP=1` so it can't be skipped).
- Library code under `src/` (except the `src/chat` demo) imports only `node:` built-ins; `test/pure.independence.test.ts` enforces this.
- New behavior comes with tests; protocol or crypto changes need a known-answer vector or a cross-implementation test.
- Commit messages use `<type>: <imperative description>` (e.g. `fix: reject truncated GCM tags`).

## License

Apache-2.0
