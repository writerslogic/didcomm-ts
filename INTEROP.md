# Interoperability

didcomm-ts is an independent DIDComm v2 implementation. Its JOSE layer
(ECDH-ES and ECDH-1PU + A256KW, ConcatKDF, A256CBC-HS512 / A256GCM / XC20P,
EdDSA / ES256 / ES256K JWS), CBOR codec, DID key handling and transports are
written in this repository over `node:crypto`, with no runtime dependencies.
`test/pure.independence.test.ts` enforces that every published module imports
only `node:` built-ins and that `package.json` has no `dependencies`.

didcomm-rust (via its `didcomm` WASM package) and didcomm-python appear only
as dev dependencies: they are the independent counterparties in the tests
below.

All results come from `npm test` unless marked otherwise. Counterparty
versions: didcomm-rust via `didcomm` 0.4.1 (WASM), didcomm-python 0.3.2
(authlib 1.8.0), `@aviarytech/didcomm-core` 0.1.35.

## Known-answer vectors (`test/pure.vectors.test.ts`, 18 tests)

| Vector | Source | Result |
| --- | --- | --- |
| AES-KW 256 | RFC 3394 §4.3 | pass |
| A256CBC-HS512 | RFC 7518 App. B.3 | pass |
| HChaCha20 | draft-irtf-cfrg-xchacha-03 §2.2.1 | pass |
| XChaCha20-Poly1305 (XC20P) | draft-irtf-cfrg-xchacha-03 App. A.3.1 | pass |
| ConcatKDF | askar `expected_1pu_output` | pass |
| ECDH-1PU X25519 with content tag (Z = Ze ‖ Zs, tag in SuppPubInfo) | draft-madden-jose-ecdh-1pu-04 App. B | pass |
| ECDH-1PU P-256 | askar `expected_1pu_direct_output` | pass |
| didcomm-rust encrypted vectors: anoncrypt XC20P (X25519, P-256), authcrypt (X25519, P-256) | didcomm-rust `src/test_vectors` @ 4388350 | all 4 decrypt |
| didcomm-rust signed vectors: EdDSA, ES256, ES256K | same | all 4 verify |
| Invalid epk point, tampered ciphertext | same | rejected |
| didcomm-rust `from_prior` JWTs: valid, malformed, bad signature | same | valid one verifies; both invalid ones rejected (`test/fromPrior.test.ts`) |

CBOR (`test/cbor.test.ts`, 41 tests) is checked against RFC 8949 Appendix A
plus malformed-input cases (truncation, oversized lengths, indefinite
lengths, duplicate keys, excess nesting, trailing bytes), and envelopes are
decoded identically by an independent CBOR library.

## Cross-implementation matrix

`→` means "packed by left, unpacked by right". Every cell runs in both
directions unless noted.

### didcomm-ts ↔ didcomm-rust (`test/pure.interop-wasm.test.ts`, 33 tests)

| | X25519 | P-256 |
| --- | --- | --- |
| Authcrypt (ECDH-1PU+A256KW, A256CBC-HS512) | pass | pass |
| Anoncrypt (ECDH-ES+A256KW) | pass | pass |
| Anoncrypt `didcomm-ts → rust` with A256CBC-HS512 / A256GCM / XC20P | pass | pass |
| Authcrypt + EdDSA JWS (non-repudiation) | pass | pass |
| CBOR-encoded authcrypt | pass | pass |
| One envelope to 3 keyAgreement keys, each member decrypts in rust | pass (X25519) | |

DID rotation and plaintext (`test/fromPrior.test.ts`): a `from_prior` JWT packed
by didcomm-ts inside an authcrypt envelope is verified by didcomm-rust's
`Message.unpack`; one packed by didcomm-rust's `FromPrior.pack` is verified by
didcomm-ts; didcomm-rust parses didcomm-ts plaintext messages.

didcomm-rust encrypts only to X25519 and P-256, so P-384/P-521 have no rust cell.

### didcomm-ts ↔ didcomm-python (`test/pure.interop-python.test.ts`, 22 tests)

| | X25519 | P-256 | P-384 | P-521 |
| --- | --- | --- | --- | --- |
| Authcrypt | pass | pass | pass | pass |
| Anoncrypt A256CBC-HS512 | pass | pass | pass | pass |
| Anoncrypt A256GCM | pass | pass | pass | pass |
| Anoncrypt XC20P | pass | pass | pass | pass |
| Authcrypt + EdDSA JWS, `didcomm-ts → python` | pass | | | |
| Protected sender (anoncrypt ⊃ authcrypt) + EdDSA JWS, `python → didcomm-ts` | pass | | | |

Runs through `test/interop/python/driver.py` (uv project with a lockfile); CI
sets `DIDCOMM_TS_REQUIRE_INTEROP=1` so a missing `uv` fails instead of skipping.

Finding: didcomm-python (authlib) emits P-521 `epk` coordinates with leading
zero bytes stripped (65 bytes instead of the 66 required by RFC 7518
§6.2.1.2). didcomm-ts accepts the short form by left-padding before on-curve
validation; it always emits full-length coordinates.

### didcomm-ts ↔ aviarytech/didcomm (`npm run interop:aviary`)

Not interoperable, and the cause is the aviarytech format: didcomm-rust fails the same cells.

```
{"aviaryProtectedHeader":{"enc":"XC20P"},"aviaryRecipientHeader":["kid","alg","epk","apu","apv"]}
{"cell":"aviary -> didcomm-ts","ok":false,"error":"Unsupported JWE alg: undefined"}
{"cell":"didcomm-ts -> aviary","ok":false,"error":"\"epk\" must be an object."}
{"cell":"aviary -> didcomm-rust","ok":false,"error":"Malformed: Unable parse protected header: missing field `alg` at line 1 column 15"}
{"cell":"didcomm-rust -> aviary","ok":false,"error":"\"epk\" must be an object."}
```

`@aviarytech/didcomm-core` 0.1.35 (its latest release, April 2022) supports anoncrypt
over X25519 only, using a pre-final JWE profile: the protected header holds
only `enc`, while `alg`, `epk`, `apu` (the ephemeral key) and `apv` (the
recipient kid) sit in each recipient's unprotected header. DIDComm v2 requires
`alg`, `epk` and `apv = SHA-256(sorted kids)` in the shared protected header.
Its `@aviarytech/did-core` dependency also fails at runtime for
`JsonWebKey2020` methods, so the probe wraps keys with
`@aviarytech/crypto-core`'s `JsonWebKey` directly; aviarytech's JWE code runs
unmodified.

## `from_prior` verification notes

- `FROM_PRIOR_JWT_INVALID_SIGNATURE` differs from the valid vector only in the
  unused padding bits of the signature's last base64url character; both decode
  to identical bytes. didcomm-rust rejects it because its decoder requires
  canonical base64url. didcomm-ts now does the same for every base64url value,
  so a signed value has exactly one valid encoding.
- The valid vector has `exp` (1234) before `nbf` (12345), so no clock time
  satisfies both; didcomm-rust doesn't check times. didcomm-ts enforces them in
  `unpack` and verifies the vector with `unpackFromPrior(jwt, did, null)`.
- didcomm-ts requires `iss` to be the DID of the key that signed the JWT and
  rejects a `from_prior` signed by any other DID's key (tested with a forged
  JWT).

## Live mediator round trip

`npm run interop:live` (`scripts/live-interop.mjs --block-wasm`) runs
mediate → send → pickup → ack against `did:web:mediator.wyvrn.app` with two
fresh `did:key` X25519 identities, while a module hook makes any attempt to
load didcomm-rust fail. The receiver requests mediation (Coordinate Mediation)
and registers its `did:key` and the `did:peer:2` it publishes (routed through
the mediator) as recipients. The sender authcrypts to that `did:peer:2`,
forward-wraps the envelope (anoncrypt to `did:web:mediator.wyvrn.app#key-2`)
and POSTs it. The receiver picks it up (Pickup 3.0), decrypts it and acks.

Three consecutive runs on the zero-dependency build:

| Started (UTC) | Receiver | Sender | Message id | Pickup attachment id | Forward HTTP | Queued after ack |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-10-09T05:50:18.014Z | `did:key:z6LSfWbTMQc3dQCDBq8E33npR2K55ZK6dMYn6BNr3cmAi1U7` | `did:key:z6LSmNAQSh6WjFUTCqrxTkZj17kZNrcf7HQzKPeVefrz37u8` | `7e17c274-6a86-4cc0-b554-fab09ed65ef6` | `24f44b46-6c45-4720-b154-30c650bcaac2` | 200 | 0 |
| 2026-10-09T05:50:28.149Z | `did:key:z6LScpouqmByGRK6QxFgiwvUKErzL6VoaX95ueNwA12vjs1U` | `did:key:z6LSkHXYuinm8tE2Hq5VtdtFFQMXVF22oe4XthNzN8YrDwrX` | `fbc6694f-de04-4261-aac7-5238c42a130d` | `1507ff4f-29b6-492e-bff4-2215407a970e` | 200 | 0 |
| 2026-10-09T05:50:32.881Z | `did:key:z6LSnQDUxrc1psa5iDqs3Dq94ZNQeCfS2hpyHGLatyXygCK7` | `did:key:z6LSbqhwwL4ZqaCBeDq3r5BJjauhFLSdgAHkuP9Xva9t8LjH` | `cedab45a-35c7-4d55-b1e1-41632510c0b3` | `4e2c2ca2-2465-4835-b93d-09548b81829a` | 200 | 0 |

Full log of the first run:

```json
{
  "mediator": "did:web:mediator.wyvrn.app",
  "wasmBlocked": true,
  "startedAt": "2026-10-09T05:50:18.014Z",
  "steps": [
    {
      "step": "mediate",
      "at": "2026-10-09T05:50:20.696Z",
      "receiverDidKey": "did:key:z6LSfWbTMQc3dQCDBq8E33npR2K55ZK6dMYn6BNr3cmAi1U7",
      "receiverDidPeer": "did:peer:2.Ez6LSfWbTMQc3dQCDBq8E33npR2K55ZK6dMYn6BNr3cmAi1U7.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9tZWRpYXRvci53eXZybi5hcHAiLCJyIjpbImRpZDp3ZWI6bWVkaWF0b3Iud3l2cm4uYXBwIl19",
      "routingDids": [
        "did:web:mediator.wyvrn.app"
      ],
      "recipientUpdates": {
        "did:key:z6LSfWbTMQc3dQCDBq8E33npR2K55ZK6dMYn6BNr3cmAi1U7": "success",
        "did:peer:2.Ez6LSfWbTMQc3dQCDBq8E33npR2K55ZK6dMYn6BNr3cmAi1U7.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9tZWRpYXRvci53eXZybi5hcHAiLCJyIjpbImRpZDp3ZWI6bWVkaWF0b3Iud3l2cm4uYXBwIl19": "success"
      },
      "mediatorEndpoint": "https://mediator.wyvrn.app"
    },
    {
      "step": "send",
      "at": "2026-10-09T05:50:21.078Z",
      "senderDidKey": "did:key:z6LSmNAQSh6WjFUTCqrxTkZj17kZNrcf7HQzKPeVefrz37u8",
      "messageId": "7e17c274-6a86-4cc0-b554-fab09ed65ef6",
      "innerRecipientKids": [
        "did:peer:2.Ez6LSfWbTMQc3dQCDBq8E33npR2K55ZK6dMYn6BNr3cmAi1U7.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9tZWRpYXRvci53eXZybi5hcHAiLCJyIjpbImRpZDp3ZWI6bWVkaWF0b3Iud3l2cm4uYXBwIl19#key-1"
      ],
      "forwardRecipientKids": [
        "did:web:mediator.wyvrn.app#key-2"
      ],
      "forwardEnvelopeSha256": "0ad2187c9fa218780ac38d500e8f95039b72f945da3b4b1b09edf4744a207ed1",
      "httpStatus": 200
    },
    {
      "step": "pickup",
      "at": "2026-10-09T05:50:21.987Z",
      "delivered": [
        {
          "attachmentId": "24f44b46-6c45-4720-b154-30c650bcaac2",
          "messageId": "7e17c274-6a86-4cc0-b554-fab09ed65ef6",
          "senderKey": "did:key:z6LSmNAQSh6WjFUTCqrxTkZj17kZNrcf7HQzKPeVefrz37u8#z6LSmNAQSh6WjFUTCqrxTkZj17kZNrcf7HQzKPeVefrz37u8",
          "recipientKey": "did:peer:2.Ez6LSfWbTMQc3dQCDBq8E33npR2K55ZK6dMYn6BNr3cmAi1U7.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9tZWRpYXRvci53eXZybi5hcHAiLCJyIjpbImRpZDp3ZWI6bWVkaWF0b3Iud3l2cm4uYXBwIl19#key-1"
        }
      ]
    },
    {
      "step": "ack",
      "at": "2026-10-09T05:50:22.516Z",
      "acknowledgedAttachmentIds": [
        "24f44b46-6c45-4720-b154-30c650bcaac2"
      ],
      "remainingQueued": 0
    }
  ],
  "result": "ok",
  "finishedAt": "2026-10-09T05:50:22.516Z"
}
```
