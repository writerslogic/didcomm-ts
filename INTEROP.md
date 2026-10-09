# Interoperability

didcomm-ts ships two DIDComm v2 envelope backends with the same API:

| Backend | Import | Crypto |
| --- | --- | --- |
| `core` | `@writerslogic/didcomm-ts` (`core` namespace) | didcomm-rust via the `didcomm` WASM package |
| `pure` | `@writerslogic/didcomm-ts/pure` | Own JOSE implementation (ECDH-ES/ECDH-1PU + A256KW, ConcatKDF, A256CBC-HS512/A256GCM/XC20P, EdDSA/ES256/ES256K JWS) over `@noble/curves`, `@noble/ciphers`, `@noble/hashes` |

`pure` never loads `didcomm`: `test/pure.independence.test.ts` walks its import
graph, and importing `@writerslogic/didcomm-ts/pure` with `didcomm` blocked by a
module hook succeeds.

All results below are from automated tests in this repository (`npm test`)
unless marked otherwise. Counterparty versions: didcomm-rust via `didcomm`
0.4.1 (WASM), didcomm-python 0.3.2 (authlib 1.8.0), `@aviarytech/didcomm-core`
0.1.35.

## Known-answer vectors (`test/pure.vectors.test.ts`)

| Vector | Source | Result |
| --- | --- | --- |
| AES-KW 256 | RFC 3394 §4.3 | pass |
| A256CBC-HS512 | RFC 7518 App. B.3 | pass |
| ConcatKDF | askar `expected_1pu_output` | pass |
| ECDH-1PU X25519 with content tag (Z = Ze ‖ Zs, tag in SuppPubInfo) | draft-madden-jose-ecdh-1pu-04 App. B | pass |
| ECDH-1PU P-256 | askar `expected_1pu_direct_output` | pass |
| didcomm-rust encrypted vectors: anoncrypt XC20P (X25519, P-256), authcrypt (X25519, P-256) | didcomm-rust `src/test_vectors` @ 4388350 | `pure` decrypts all 4 |
| didcomm-rust signed vectors: EdDSA, ES256, ES256K | same | `pure` verifies all 4 |
| Invalid epk point | same | rejected |

## Cross-implementation matrix

`→` means "packed by left, unpacked by right". Every cell runs in both
directions unless noted.

### pure ↔ didcomm-rust (`test/pure.interop-wasm.test.ts`, 33 tests)

| | X25519 | P-256 |
| --- | --- | --- |
| Authcrypt (ECDH-1PU+A256KW, A256CBC-HS512) | pass | pass |
| Anoncrypt (ECDH-ES+A256KW) | pass | pass |
| Anoncrypt `pure → rust` with A256CBC-HS512 / A256GCM / XC20P | pass | pass |
| Authcrypt + EdDSA JWS (non-repudiation) | pass | pass |
| CBOR-encoded authcrypt | pass | pass |
| One envelope to 3 keyAgreement keys, each member decrypts in rust | pass (X25519) | |

didcomm-rust encrypts only to X25519 and P-256, so P-384/P-521 have no rust cell.

### pure ↔ didcomm-python (`test/pure.interop-python.test.ts`, 22 tests)

| | X25519 | P-256 | P-384 | P-521 |
| --- | --- | --- | --- | --- |
| Authcrypt | pass | pass | pass | pass |
| Anoncrypt A256CBC-HS512 | pass | pass | pass | pass |
| Anoncrypt A256GCM | pass | pass | pass | pass |
| Anoncrypt XC20P | pass | pass | pass | pass |
| Authcrypt + EdDSA JWS, `pure → python` | pass | | | |
| Protected sender (anoncrypt ⊃ authcrypt) + EdDSA JWS, `python → pure` | pass | | | |

Runs through `test/interop/python/driver.py` (uv project with a lockfile); CI
sets `DIDCOMM_TS_REQUIRE_INTEROP=1` so a missing `uv` fails instead of skipping.

Finding: didcomm-python (authlib) emits P-521 `epk` coordinates with leading
zero bytes stripped (65 bytes instead of the 66 required by RFC 7518
§6.2.1.2). `pure` accepts the short form by left-padding before on-curve
validation; it always emits full-length coordinates.

### pure ↔ aviarytech/didcomm (`npm run interop:aviary`)

Not interoperable, and the cause is the aviarytech format, not either
DIDComm v2 implementation here: didcomm-rust fails the same cells.

```
{"aviaryProtectedHeader":{"enc":"XC20P"},"aviaryRecipientHeader":["kid","alg","epk","apu","apv"]}
{"cell":"aviary -> pure","ok":false,"error":"Unsupported JWE alg: undefined"}
{"cell":"pure -> aviary","ok":false,"error":"\"epk\" must be an object."}
{"cell":"aviary -> wasm","ok":false,"error":"Malformed: Unable parse protected header: missing field `alg` at line 1 column 15"}
{"cell":"wasm -> aviary","ok":false,"error":"\"epk\" must be an object."}
```

`@aviarytech/didcomm-core` 0.1.35 (its only release, 2022) supports anoncrypt
over X25519 only, using a pre-final JWE profile: the protected header holds
only `enc`, while `alg`, `epk`, `apu` (the ephemeral key) and `apv` (the
recipient kid) sit in each recipient's unprotected header. DIDComm v2 requires
`alg`, `epk` and `apv = SHA-256(sorted kids)` in the shared protected header.
Its `@aviarytech/did-core` dependency also fails at runtime for
`JsonWebKey2020` methods, so the probe wraps keys with
`@aviarytech/crypto-core`'s `JsonWebKey` directly; aviarytech's JWE code runs
unmodified.

## Live mediator round trip

`npm run interop:live` (`scripts/live-interop.mjs`) runs mediate → send →
pickup → ack against a real mediator with fresh identities and prints a
JSON log of timestamps, DIDs and message/attachment ids.

### Recorded runs against `did:web:mediator.wyvrn.app`

Each run used two fresh `did:key` X25519 identities. The receiver requests mediation, registers its `did:key` and the `did:peer:2` it publishes (routed through the mediator) as recipients; the sender authcrypts to that `did:peer:2`, forward-wraps the envelope (anoncrypt to `did:web:mediator.wyvrn.app#key-2`), and POSTs it; the receiver picks it up (Pickup 3.0), decrypts it, and acks.

| Sender → receiver backend | WASM blocked | Started (UTC) | Message id | Pickup attachment id | Remaining after ack |
| --- | --- | --- | --- | --- | --- |
| pure → pure | yes | 2026-10-09T05:04:27.826Z | `024ebecc-eafd-45a9-a8fa-32a247985e62` | `d6652ac2-45eb-491a-acdd-8c0aaf606b50` | 0 |
| wasm → wasm | no | 2026-10-09T05:04:09.282Z | `c80ce31b-e159-427e-b686-0a3066103afd` | `081ac87d-7011-4878-b837-02f23b7edae7` | 0 |
| pure → wasm | no | 2026-10-09T05:04:40.781Z | `66e6d061-3860-4636-8f65-adb6143b1a5c` | `873c7b21-4122-4c21-963f-f6e5bb6a40f3` | 0 |

Full log of the pure run (`node scripts/live-interop.mjs --backend pure --block-wasm`):

```json
{
  "mediator": "did:web:mediator.wyvrn.app",
  "senderBackend": "pure",
  "receiverBackend": "pure",
  "wasmBlocked": true,
  "startedAt": "2026-10-09T05:04:27.826Z",
  "steps": [
    {
      "step": "mediate",
      "at": "2026-10-09T05:04:31.318Z",
      "receiverDidKey": "did:key:z6LSiGEeAKSCcHo9NRGDeBJestqFK8s3fVdkzJTW3ciMaURF",
      "receiverDidPeer": "did:peer:2.Ez6LSiGEeAKSCcHo9NRGDeBJestqFK8s3fVdkzJTW3ciMaURF.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9tZWRpYXRvci53eXZybi5hcHAiLCJyIjpbImRpZDp3ZWI6bWVkaWF0b3Iud3l2cm4uYXBwIl19",
      "routingDids": [
        "did:web:mediator.wyvrn.app"
      ],
      "recipientUpdates": {
        "did:key:z6LSiGEeAKSCcHo9NRGDeBJestqFK8s3fVdkzJTW3ciMaURF": "success",
        "did:peer:2.Ez6LSiGEeAKSCcHo9NRGDeBJestqFK8s3fVdkzJTW3ciMaURF.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9tZWRpYXRvci53eXZybi5hcHAiLCJyIjpbImRpZDp3ZWI6bWVkaWF0b3Iud3l2cm4uYXBwIl19": "success"
      },
      "mediatorEndpoint": "https://mediator.wyvrn.app"
    },
    {
      "step": "send",
      "at": "2026-10-09T05:04:31.771Z",
      "senderDidKey": "did:key:z6LSpMmAz7oKCUJiPJpWTzJuQkKmFbbmF1Wi9VBNNDXm1bUc",
      "messageId": "024ebecc-eafd-45a9-a8fa-32a247985e62",
      "innerRecipientKids": [
        "did:peer:2.Ez6LSiGEeAKSCcHo9NRGDeBJestqFK8s3fVdkzJTW3ciMaURF.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9tZWRpYXRvci53eXZybi5hcHAiLCJyIjpbImRpZDp3ZWI6bWVkaWF0b3Iud3l2cm4uYXBwIl19#key-1"
      ],
      "forwardRecipientKids": [
        "did:web:mediator.wyvrn.app#key-2"
      ],
      "forwardEnvelopeSha256": "fb05fdb828a0512bc7f44089412cae65c91a1a5faf4b5959f920d7c2dff223db",
      "httpStatus": 200
    },
    {
      "step": "pickup",
      "at": "2026-10-09T05:04:32.785Z",
      "delivered": [
        {
          "attachmentId": "d6652ac2-45eb-491a-acdd-8c0aaf606b50",
          "messageId": "024ebecc-eafd-45a9-a8fa-32a247985e62",
          "senderKey": "did:key:z6LSpMmAz7oKCUJiPJpWTzJuQkKmFbbmF1Wi9VBNNDXm1bUc#z6LSpMmAz7oKCUJiPJpWTzJuQkKmFbbmF1Wi9VBNNDXm1bUc",
          "recipientKey": "did:peer:2.Ez6LSiGEeAKSCcHo9NRGDeBJestqFK8s3fVdkzJTW3ciMaURF.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9tZWRpYXRvci53eXZybi5hcHAiLCJyIjpbImRpZDp3ZWI6bWVkaWF0b3Iud3l2cm4uYXBwIl19#key-1"
        }
      ]
    },
    {
      "step": "ack",
      "at": "2026-10-09T05:04:33.460Z",
      "acknowledgedAttachmentIds": [
        "d6652ac2-45eb-491a-acdd-8c0aaf606b50"
      ],
      "remainingQueued": 0
    }
  ],
  "result": "ok",
  "finishedAt": "2026-10-09T05:04:33.461Z"
}
```
