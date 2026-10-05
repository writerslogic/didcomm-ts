/**
 * Full-stack end-to-end test: core (pack/unpack) + routing (selectRoutingPath)
 * + transport (listenHttp/sendHttp) exercised together, where today each
 * module is only unit-tested in isolation.
 *
 * KNOWN LIMITATION (see jest.config.js's header comment): the installed
 * `didcomm@0.4.1` package ships only a wasm-pack "bundler" target
 * (`node_modules/didcomm/index.js` does `import * as wasm from
 * "./index_bg.wasm"`), which Jest's Node-ESM module loader cannot resolve.
 * `src/core/envelope.ts` imports `didcomm` directly, so any test that goes
 * through `packAuthcrypt`/`unpack` fails at that import, independent of this
 * test's own logic. This file still type-checks and runs the routing +
 * transport portions for real; the core-dependent portions are included so
 * the gap is visible (and ready to pass unmodified) once `didcomm` ships a
 * Node-resolvable build or Jest gains WASM-ESM support.
 *
 * This file does not modify jest.config.js or any src/ file.
 */
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import { jest } from '@jest/globals';
import type {
  packAuthcrypt as PackAuthcryptFn,
  unpack as UnpackFn,
  DIDDoc as CoreDidDoc,
  DidResolver,
  Secret,
  SecretsResolver,
  PlaintextMessage,
} from '../src/core/index.js';
import {
  selectRoutingPath,
  type DIDDoc as RoutingDidDoc,
  type ServiceEndpointObject,
} from '../src/routing/index.js';
import { listenHttp, sendHttp } from '../src/transport/index.js';

// ---------------------------------------------------------------------------
// Bounded workaround for the known issue documented in jest.config.js:
// `didcomm@0.4.1` ships only a wasm-pack "bundler" target
// (`import * as wasm from "./index_bg.wasm"` in its index.js), which Jest's
// Node-ESM loader cannot resolve. Rather than changing jest.config.js or any
// src/ file, this test loads the REAL wasm binary itself (no faked crypto)
// and mocks the `didcomm` module specifier to expose it, so packAuthcrypt /
// unpack can run under Jest. src/core/index.ts is imported dynamically below
// (after the mock is registered) because static imports are hoisted above
// jest.unstable_mockModule.
// ---------------------------------------------------------------------------
const require = createRequire(import.meta.url);

jest.unstable_mockModule('didcomm', async () => {
  const path = await import('node:path');
  const bgPath = require.resolve('didcomm/index_bg.js');
  // Resolve the binary's path via the package directory rather than the
  // bare `didcomm/index_bg.wasm` specifier: Jest's sandboxed `require`
  // honors jest.config.js's `moduleNameMapper`, so a `\.wasm$` mapper added
  // elsewhere in this config would otherwise redirect that specifier to its
  // own shim instead of the real file.
  const wasmPath = path.join(path.dirname(require.resolve('didcomm/package.json')), 'index_bg.wasm');
  const bg = await import(bgPath);
  const wasmModule = await WebAssembly.compile(fs.readFileSync(wasmPath));
  const instance = await WebAssembly.instantiate(wasmModule, { './index_bg.js': bg });
  bg.__wbg_set_wasm(instance.exports);
  return bg;
});

let packAuthcrypt: typeof PackAuthcryptFn;
let unpack: typeof UnpackFn;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function generateX25519Key(kid: string): { kid: string; publicKeyJwk: unknown; secret: Secret } {
  const { publicKey, privateKey } = generateKeyPairSync('x25519');
  return {
    kid,
    publicKeyJwk: publicKey.export({ format: 'jwk' }),
    secret: { id: kid, type: 'JsonWebKey2020', privateKeyJwk: privateKey.export({ format: 'jwk' }) },
  };
}

class MapDidResolver implements DidResolver {
  constructor(private readonly docs: Map<string, CoreDidDoc>) {}
  async resolve(did: string): Promise<CoreDidDoc | null> {
    return this.docs.get(did) ?? null;
  }
}

class MapSecretsResolver implements SecretsResolver {
  constructor(private readonly secrets: Map<string, Secret>) {}
  async get_secret(secretId: string): Promise<Secret | null> {
    return this.secrets.get(secretId) ?? null;
  }
  async find_secrets(secretIds: string[]): Promise<string[]> {
    return secretIds.filter((id) => this.secrets.has(id));
  }
}

describe('e2e: core + routing + transport', () => {
  jest.setTimeout(20000);

  beforeAll(async () => {
    const core = await import('../src/core/index.js');
    packAuthcrypt = core.packAuthcrypt;
    unpack = core.unpack;
  });

  it('packs a multi-device envelope, delivers it over real HTTP using routing-selected endpoints, and both devices independently decrypt it', async () => {
    // --- Start the real HTTP receiver first: the endpoint it binds to is
    // what routing's selected path must agree with. ---
    const received: Array<{ bytes: Uint8Array; contentType: string }> = [];
    let resolveReceived: () => void;
    let receivedPromise = new Promise<void>((res) => {
      resolveReceived = res;
    });

    const { port, close } = await listenHttp(0, (bytes, contentType) => {
      received.push({ bytes, contentType });
      resolveReceived();
    });
    const receiverUrl = `http://127.0.0.1:${port}/`;

    try {
      // --- Sender identity ---
      const senderDid = 'did:example:sender';
      const senderKey = generateX25519Key(`${senderDid}#key-1`);
      const senderDoc: CoreDidDoc = {
        id: senderDid,
        keyAgreement: [senderKey.kid],
        authentication: [],
        verificationMethod: [
          { id: senderKey.kid, type: 'JsonWebKey2020', controller: senderDid, publicKeyJwk: senderKey.publicKeyJwk },
        ],
        service: [],
      };

      // --- Recipient: 1 logical recipient, 2 device keys under ONE DID Doc
      // (per envelope.ts's documented single-DID-Doc constraint for sharing
      // one CEK across multiple keyAgreement keys). ---
      const recipientDid = 'did:example:recipient';
      const deviceA = generateX25519Key(`${recipientDid}#device-a`);
      const deviceB = generateX25519Key(`${recipientDid}#device-b`);

      // Service entries shared verbatim between the core DID Doc (what
      // packAuthcrypt/unpack see) and the routing DID Doc (what
      // selectRoutingPath sees) via a type that satisfies both interfaces
      // structurally, so there is no cast and no risk of the two drifting.
      // Neither service declares routingKeys: PackOptions.forward in
      // envelope.ts is documented as not implementing the Forward protocol,
      // so a mediated path cannot be exercised end to end here (flagged gap).
      const services: Array<{ id: string; type: string; serviceEndpoint: ServiceEndpointObject }> = [
        { id: `${recipientDid}#device-a`, type: 'DIDCommMessaging', serviceEndpoint: { uri: receiverUrl } },
        {
          id: `${recipientDid}#device-b`,
          type: 'DIDCommMessaging',
          serviceEndpoint: { uri: 'https://device-b.example.com/didcomm' },
        },
      ];

      const recipientDoc: CoreDidDoc = {
        id: recipientDid,
        keyAgreement: [deviceA.kid, deviceB.kid],
        authentication: [],
        verificationMethod: [
          { id: deviceA.kid, type: 'JsonWebKey2020', controller: recipientDid, publicKeyJwk: deviceA.publicKeyJwk },
          { id: deviceB.kid, type: 'JsonWebKey2020', controller: recipientDid, publicKeyJwk: deviceB.publicKeyJwk },
        ],
        service: services,
      };

      const sharedDidResolver = new MapDidResolver(
        new Map<string, CoreDidDoc>([
          [senderDid, senderDoc],
          [recipientDid, recipientDoc],
        ]),
      );
      const senderSecrets = new MapSecretsResolver(new Map([[senderKey.kid, senderKey.secret]]));

      // --- Routing: resolve device-a's path and send to the endpoint
      // routing actually selected, proving routing and transport agree on
      // where the message is delivered. ---
      const routingDoc: RoutingDidDoc = { id: recipientDid, service: services };

      const deviceAPath = selectRoutingPath(routingDoc, 'device-a');
      const deviceBPath = selectRoutingPath(routingDoc, 'device-b');
      expect(deviceAPath.endpoint).toBe(receiverUrl);
      expect(deviceAPath.mediators).toEqual([]);
      expect(deviceBPath.endpoint).not.toBe(deviceAPath.endpoint);
      expect(deviceBPath.mediators).toEqual([]);

      const allPaths = selectRoutingPath(routingDoc);
      expect(allPaths).toHaveLength(2);
      // At least one device's routing-selected endpoint matches the receiver
      // URL actually used for delivery below.
      expect(allPaths.some((p) => p.endpoint === receiverUrl)).toBe(true);

      // --- Core: pack one authcrypt envelope addressed to BOTH device keys. ---
      const plaintext: PlaintextMessage = {
        id: randomUUID(),
        typ: 'application/didcomm-plain+json',
        type: 'https://didcomm.org/basicmessage/2.0/message',
        body: { content: 'hello from the full stack' },
      };

      const envelope = await packAuthcrypt(plaintext, [deviceA.kid, deviceB.kid], senderDid, {
        did: sharedDidResolver,
        secrets: senderSecrets,
      });
      expect(typeof envelope).toBe('string');

      const jwe = JSON.parse(envelope as string);
      expect(Array.isArray(jwe.recipients)).toBe(true);
      expect(jwe.recipients).toHaveLength(2);

      const envelopeBytes = new TextEncoder().encode(envelope as string);

      // --- Transport: send to routing's selected endpoint for device-a,
      // which is the same server listenHttp bound above. ---
      const res = await sendHttp(deviceAPath.endpoint, envelopeBytes, 'application/didcomm-encrypted+json');
      expect(res.status).toBe(202);

      await receivedPromise;
      expect(received).toHaveLength(1);
      expect(received[0].contentType).toBe('application/didcomm-encrypted+json');

      // --- Unpack the bytes that actually arrived over the wire, once per
      // device, each using only that device's own secret. ---
      const deviceASecrets = new MapSecretsResolver(new Map([[deviceA.kid, deviceA.secret]]));
      const deviceBSecrets = new MapSecretsResolver(new Map([[deviceB.kid, deviceB.secret]]));

      const resultA = await unpack(received[0].bytes, { did: sharedDidResolver, secrets: deviceASecrets });
      const resultB = await unpack(received[0].bytes, { did: sharedDidResolver, secrets: deviceBSecrets });

      expect(resultA.message.body).toEqual({ content: 'hello from the full stack' });
      expect(resultA.message.id).toBe(plaintext.id);
      expect(resultA.senderKey).toBe(senderKey.kid);
      expect(resultA.recipientKey).toBe(deviceA.kid);

      expect(resultB.message.body).toEqual({ content: 'hello from the full stack' });
      expect(resultB.message.id).toBe(plaintext.id);
      expect(resultB.senderKey).toBe(senderKey.kid);
      expect(resultB.recipientKey).toBe(deviceB.kid);

      expect(resultA.recipientKey).not.toBe(resultB.recipientKey);
    } finally {
      await close();
    }
  });
});
