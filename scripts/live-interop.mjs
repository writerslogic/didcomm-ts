#!/usr/bin/env node
/**
 * Live mediate -> send -> pickup -> ack round trip against a real DIDComm v2
 * mediator, printing a JSON log (timestamps, DIDs, message/attachment ids)
 * suitable for INTEROP.md. Two fresh did:key identities are created in
 * temporary directories: the receiver registers with the mediator and
 * publishes a did:peer:2 routed through it; the sender authcrypts to that
 * DID and forward-wraps through the mediator.
 *
 * Usage:
 *   npm run build
 *   node scripts/live-interop.mjs [--mediator did:web:mediator.wyvrn.app] [--block-wasm]
 *
 * --block-wasm installs a module hook that throws if `didcomm` (didcomm-rust
 * WASM, a dev dependency used only by the interop tests) is ever resolved.
 *
 * Exits 0 only if the sent message id is picked up, decrypted, and acked.
 */
import { createHash, randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

const DIST = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist');
const PICKUP_ATTEMPTS = 10;
const PICKUP_DELAY_MS = 1000;

const { values: args } = parseArgs({
  options: {
    mediator: { type: 'string', default: 'did:web:mediator.wyvrn.app' },
    'block-wasm': { type: 'boolean', default: false },
  },
});

if (args['block-wasm']) {
  const { registerHooks } = await import('node:module');
  registerHooks({
    resolve(specifier, context, next) {
      if (specifier === 'didcomm' || specifier.endsWith('.wasm')) throw new Error(`blocked WASM import: ${specifier}`);
      return next(specifier, context);
    },
  });
}

const core = await import(join(DIST, 'core/index.js'));

const { loadOrCreateIdentity, didKeyFragment, didKeyToX25519PublicJwk } = await import(join(DIST, 'chat/keys.js'));
const { resolveDidWeb } = await import(join(DIST, 'chat/didWeb.js'));
const { resolveDidPeer, resolveDidPeer4, buildDidPeer2 } = await import(join(DIST, 'chat/didPeer.js'));
const { requestMediation, updateRecipient } = await import(join(DIST, 'chat/mediation.js'));
const { requestStatus, requestDelivery, acknowledgeReceived } = await import(join(DIST, 'chat/pickup.js'));
const { resolveDirectEndpoint } = await import(join(DIST, 'chat/didcommRpc.js'));
const { selectRoutingPath, wrapForwardChain } = await import(join(DIST, 'routing/index.js'));
const { sendHttp } = await import(join(DIST, 'transport/index.js'));

const tempDirs = [];

function party() {
  const dir = mkdtempSync(join(tmpdir(), 'didcomm-ts-live-'));
  tempDirs.push(dir);
  const identity = loadOrCreateIdentity(dir);
  const ownDoc = didKeyDoc(identity.did);
  const did = {
    async resolve(target) {
      if (target === identity.did) return ownDoc;
      const method = target.split(':')[1];
      if (method === 'key') return didKeyDoc(target);
      if (method === 'web') return resolveDidWeb(target);
      if (method === 'peer') return target.startsWith('did:peer:4') ? resolveDidPeer4(target) : resolveDidPeer(target);
      throw new Error(`unsupported DID method: ${target}`);
    },
  };
  // One X25519 key, addressable by its did:key fragment or the did:peer:2 fragment it publishes.
  const secrets = {
    get_secret: async (id) => ({ id, type: 'JsonWebKey2020', privateKeyJwk: identity.secretJwk }),
    find_secrets: async (ids) => ids,
  };
  return { identity, did, secrets, ctx: { selfDid: identity.did, did, secrets } };
}

function didKeyDoc(target) {
  const kid = didKeyFragment(target);
  return {
    id: target,
    keyAgreement: [kid],
    authentication: [],
    verificationMethod: [{ id: kid, type: 'JsonWebKey2020', controller: target, publicKeyJwk: didKeyToX25519PublicJwk(target) }],
    service: [],
  };
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const log = {
  mediator: args.mediator,
  wasmBlocked: args['block-wasm'],
  startedAt: new Date().toISOString(),
  steps: [],
};
const step = (name, data) => log.steps.push({ step: name, at: new Date().toISOString(), ...data });

let exitCode = 1;
try {
  const receiver = party();
  const sender = party();

  const grant = await requestMediation(args.mediator, receiver.ctx);
  const update = await updateRecipient(args.mediator, receiver.identity.did, 'add', receiver.ctx);
  const mediatorEndpoint = await resolveDirectEndpoint(args.mediator, receiver.did);
  const receiverPeerDid = buildDidPeer2(receiver.identity.secretJwk.x, mediatorEndpoint, grant.routingDids);
  // Forwards name the published did:peer:2 as `next`, so it must be a registered recipient too.
  const peerUpdate = await updateRecipient(args.mediator, receiverPeerDid, 'add', receiver.ctx);
  step('mediate', {
    receiverDidKey: receiver.identity.did,
    receiverDidPeer: receiverPeerDid,
    routingDids: grant.routingDids,
    recipientUpdates: { [receiver.identity.did]: update.result, [receiverPeerDid]: peerUpdate.result },
    mediatorEndpoint,
  });

  const message = {
    id: randomUUID(),
    typ: 'application/didcomm-plain+json',
    type: 'https://didcomm.org/basicmessage/2.0/message',
    from: sender.identity.did,
    to: [receiverPeerDid],
    created_time: Math.floor(Date.now() / 1000),
    body: { content: `didcomm-ts live interop` },
  };
  const inner = await core.packAuthcrypt(message, [receiverPeerDid], sender.identity.did, sender);
  const peerDoc = await sender.did.resolve(receiverPeerDid);
  const [route] = selectRoutingPath({ id: peerDoc.id, service: peerDoc.service });
  if (!route || route.mediators.length === 0) throw new Error('receiver did:peer:2 has no mediator route');
  const wrapped = await wrapForwardChain(JSON.parse(inner), route.mediators, receiverPeerDid, core.anoncryptProvider({ did: sender.did, secrets: sender.secrets }));
  const wire = new TextEncoder().encode(JSON.stringify(wrapped));
  const response = await sendHttp(route.endpoint, wire, 'application/didcomm-encrypted+json');
  step('send', {
    senderDidKey: sender.identity.did,
    messageId: message.id,
    innerRecipientKids: JSON.parse(inner).recipients.map((r) => r.header.kid),
    forwardRecipientKids: wrapped.recipients.map((r) => r.header.kid),
    forwardEnvelopeSha256: createHash('sha256').update(wire).digest('hex'),
    httpStatus: response.status,
  });
  if (!response.ok) throw new Error(`mediator rejected forward: HTTP ${response.status}`);

  let delivered = [];
  for (let attempt = 1; attempt <= PICKUP_ATTEMPTS && delivered.length === 0; attempt++) {
    const status = await requestStatus(args.mediator, receiver.ctx);
    if (status.messageCount > 0) delivered = await requestDelivery(args.mediator, receiver.ctx, status.messageCount);
    else await sleep(PICKUP_DELAY_MS);
  }
  const received = [];
  for (const { attachmentId, envelopeBytes } of delivered) {
    const result = await core.unpack(envelopeBytes, { did: receiver.did, secrets: receiver.secrets });
    received.push({ attachmentId, messageId: result.message.id, senderKey: result.senderKey, recipientKey: result.recipientKey });
  }
  step('pickup', { delivered: received });
  const match = received.find((r) => r.messageId === message.id);
  if (!match) throw new Error(`sent message ${message.id} was not delivered`);

  const ack = await acknowledgeReceived(args.mediator, receiver.ctx, delivered.map((d) => d.attachmentId));
  step('ack', { acknowledgedAttachmentIds: delivered.map((d) => d.attachmentId), remainingQueued: ack.messageCount });
  log.result = 'ok';
  exitCode = 0;
} catch (err) {
  log.result = 'failed';
  log.error = err instanceof Error ? err.message : String(err);
} finally {
  log.finishedAt = new Date().toISOString();
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
  console.log(JSON.stringify(log, null, 2));
  process.exitCode = exitCode;
}
