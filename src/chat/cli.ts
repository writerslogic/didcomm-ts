#!/usr/bin/env node
/**
 * Minimal CLI chat demo over generic DIDComm v2.
 *
 * Usage:
 *   node dist/chat/cli.js send <peer-did> <endpoint-url> <text...> [--attach-provenance <sha256-hex>] [--provenance-url <url>]
 *   node dist/chat/cli.js listen [port]
 *   node dist/chat/cli.js serve [port]   (web chat UI, same receiver as "listen")
 *
 * Peer DIDs may be `did:key` (a bare X25519 key-agreement key, see keys.ts),
 * `did:web` (resolved over HTTPS, see didWeb.ts), or `did:peer:2`/`did:peer:4`
 * (resolved purely locally, see didPeer.ts). There is still no
 * DID-network-based *endpoint* discovery: `<endpoint-url>` is always the
 * literal HTTP destination the envelope is POSTed to. What a resolved peer
 * DID Doc's DIDCommMessaging service entry (if any) determines is routing —
 * when it declares mediators (`routingKeys`), the envelope is forward-wrapped
 * through them before being sent to that same endpoint; with no mediators,
 * the envelope is sent as-is, as before.
 */
import { randomUUID } from "node:crypto";
import { pathToFileURL, fileURLToPath } from "node:url";
import express, { type Express } from "express";
import { didKeyFragment, didKeyToX25519PublicJwk, loadOrCreateIdentity, type Identity } from "./keys.js";
import { resolveDidWeb } from "./didWeb.js";
import { resolveDidPeer, resolveDidPeer4 } from "./didPeer.js";
import { requestMediation, updateRecipient } from "./mediation.js";
import { resolveDirectEndpoint } from "./didcommRpc.js";
import { requestStatus, requestDelivery, acknowledgeReceived } from "./pickup.js";
import { buildDidPeer2 } from "./didPeer.js";
import {
  packAuthcrypt,
  packAnoncrypt,
  unpack,
  type DIDDoc,
  type DidResolver,
  type SecretsResolver,
  type PlaintextMessage as CorePlaintextMessage,
} from "../core/index.js";
import {
  selectRoutingPath,
  wrapForwardChain,
  type DIDDoc as RoutingDIDDoc,
  type AnoncryptProvider,
  type EncryptedMessage,
} from "../routing/index.js";
import { sendHttp, listenHttp, createHttpReceiver } from "../transport/index.js";
import { attachProvenance, readProvenance } from "../provenance/index.js";

/** Basic-message protocol URI (generic DIDComm v2, not interop-partner specific). */
const BASIC_MESSAGE_TYPE = "https://didcomm.org/basicmessage/2.0/message";
const DEFAULT_PORT = 8787;

function usage(): never {
  console.error(
    "usage:\n" +
      "  chat send <peer-did> <endpoint-url> <text...> [--attach-provenance <sha256-hex>] [--provenance-url <url>]\n" +
      "  chat listen [port]\n" +
      "  chat serve [port]\n" +
      "  chat mediate <mediator-did>\n" +
      "  chat pickup <mediator-did>",
  );
  process.exit(1);
}

interface SendArgs {
  peerDid: string;
  endpoint: string;
  text: string;
  attachProvenanceHash?: string;
  provenanceUrl?: string;
}

/** Parses `send`'s positional args plus its `--attach-provenance`/`--provenance-url` flags, which may be interspersed with the text words. */
function parseSendArgs(rest: string[]): SendArgs | null {
  const [peerDid, endpoint, ...tail] = rest;
  if (!peerDid || !endpoint) return null;

  const words: string[] = [];
  let attachProvenanceHash: string | undefined;
  let provenanceUrl: string | undefined;

  for (let i = 0; i < tail.length; i++) {
    const arg = tail[i];
    if (arg === "--attach-provenance") {
      attachProvenanceHash = tail[++i];
      if (!attachProvenanceHash) return null;
      continue;
    }
    if (arg === "--provenance-url") {
      provenanceUrl = tail[++i];
      if (!provenanceUrl) return null;
      continue;
    }
    words.push(arg);
  }

  if (words.length === 0) return null;
  return { peerDid, endpoint, text: words.join(" "), attachProvenanceHash, provenanceUrl };
}

/** Builds a did:key DIDDoc with a single keyAgreement verification method. */
function didKeyDoc(did: string): DIDDoc {
  const kid = didKeyFragment(did);
  return {
    id: did,
    keyAgreement: [kid],
    authentication: [],
    verificationMethod: [
      { id: kid, type: "JsonWebKey2020", controller: did, publicKeyJwk: didKeyToX25519PublicJwk(did) },
    ],
    service: [],
  };
}

/**
 * A DidResolver that resolves the local identity's own DID, `did:key` peers
 * (reusing keys.ts's own logic via `didKeyDoc`), `did:web` peers (via
 * `resolveDidWeb`), and `did:peer:2...` peers (via `resolveDidPeer`, purely
 * local — no network call). Any other DID method or did:peer numalgo throws.
 */
function combinedResolver(identity: Identity): DidResolver {
  const ownDoc = didKeyDoc(identity.did);
  return {
    async resolve(did: string): Promise<DIDDoc | null> {
      if (did === identity.did) return ownDoc;

      const method = did.split(":")[1];
      if (method === "key") {
        try {
          return didKeyDoc(did);
        } catch {
          return null;
        }
      }
      if (method === "web") {
        return resolveDidWeb(did);
      }
      if (method === "peer") {
        return did.startsWith("did:peer:4") ? resolveDidPeer4(did) : resolveDidPeer(did);
      }
      throw new Error("unsupported DID method");
    },
  };
}

/**
 * Adapts `packAnoncrypt` into routing/forward.ts's `AnoncryptProvider` shape,
 * so forward-wrap messages can be anoncrypted to a mediator's resolved key
 * using the same crypto layer as the rest of this module. `decrypt` is
 * unused by `send` (the CLI only ever wraps a forward message as a sender,
 * never unwraps one as a mediator) and throws if called.
 */
function anoncryptProvider(did: DidResolver, secrets: SecretsResolver): AnoncryptProvider {
  return {
    async encrypt(message, recipientKeyId): Promise<EncryptedMessage> {
      const plaintext: CorePlaintextMessage = { typ: "application/didcomm-plain+json", ...message };
      const packed = await packAnoncrypt(plaintext, [recipientKeyId], { did, secrets });
      const json = typeof packed === "string" ? packed : new TextDecoder().decode(packed);
      return JSON.parse(json) as EncryptedMessage;
    },
    decrypt(): never {
      throw new Error("anoncryptProvider: decrypt is not implemented (the chat CLI never acts as a mediator)");
    },
  };
}

/** A SecretsResolver backed by the local identity's one X25519 secret. */
/**
 * This identity has exactly one X25519 secret, but it can be addressed by
 * several different key ids depending on which DID form a peer encrypted
 * to (its `did:key` fragment, or a `did:peer:2` fragment this identity
 * published via `buildDidPeer2` — both reference the same underlying key).
 * So any requested `secretId` is satisfiable by this one secret; there is
 * no second key to distinguish it from. A multi-key identity would need a
 * real per-id lookup instead.
 */
function identitySecretsResolver(identity: Identity): SecretsResolver {
  return {
    async get_secret(secretId: string) {
      return { id: secretId, type: "JsonWebKey2020", privateKeyJwk: identity.secretJwk };
    },
    async find_secrets(secretIds: string[]) {
      return secretIds;
    },
  };
}

/**
 * Core of the `send` subcommand: resolves the peer, packs the authcrypt
 * envelope, forward-wraps it through mediators if the peer's DID Doc
 * declares any, and POSTs it to `endpoint`. Shared by the CLI `send`
 * command and the `serve` web UI's `POST /api/send` route — both call this
 * same function rather than duplicating its logic. Has no side effects
 * beyond the network send (no console output), and returns the raw
 * `fetch` Response so callers can inspect `res.ok` themselves.
 */
async function sendMessage(
  identity: Identity,
  peerDid: string,
  endpoint: string,
  text: string,
  options: { attachProvenanceHash?: string; provenanceUrl?: string } = {},
): Promise<globalThis.Response> {
  const did = combinedResolver(identity);
  const secrets = identitySecretsResolver(identity);

  const peerDoc = await did.resolve(peerDid);
  if (!peerDoc) throw new Error(`could not resolve peer DID: ${peerDid}`);

  const attachments = options.attachProvenanceHash
    ? [
        attachProvenance(
          { id: randomUUID(), data: { base64: Buffer.from(text, "utf8").toString("base64") } },
          { hash: { alg: "sha256", value: options.attachProvenanceHash }, url: options.provenanceUrl },
        ),
      ]
    : undefined;

  const envelope = await packAuthcrypt(
    {
      id: randomUUID(),
      typ: "application/didcomm-plain+json",
      type: BASIC_MESSAGE_TYPE,
      body: { content: text },
      from: identity.did,
      to: [peerDid],
      ...(attachments ? { attachments } : {}),
    },
    [peerDid],
    identity.did,
    { did, secrets },
  );

  // Routing: forward-wrap through the peer's mediators, if its resolved
  // DID Doc declares any (via a DIDCommMessaging service entry's
  // `routingKeys`). With no service entry, or none with mediators, behavior
  // is unchanged: the authcrypt envelope is sent as-is. `<endpoint-url>` is
  // always the literal HTTP destination either way — routing only decides
  // whether/how the bytes sent to it are forward-wrapped, not which URL they
  // go to (there is still no DID-network-based endpoint discovery).
  const routingDoc = { id: peerDoc.id, service: peerDoc.service } as unknown as RoutingDIDDoc;
  const [routingPath] = selectRoutingPath(routingDoc);

  let wireBytes: Uint8Array;
  if (routingPath && routingPath.mediators.length > 0) {
    const envelopeJson =
      typeof envelope === "string" ? envelope : new TextDecoder().decode(envelope);
    const wrapped = await wrapForwardChain(
      JSON.parse(envelopeJson) as EncryptedMessage,
      routingPath.mediators,
      peerDid,
      anoncryptProvider(did, secrets),
    );
    wireBytes = new TextEncoder().encode(JSON.stringify(wrapped));
  } else {
    wireBytes = typeof envelope === "string" ? new TextEncoder().encode(envelope) : envelope;
  }

  const res = await sendHttp(endpoint, wireBytes, "application/didcomm-encrypted+json");
  return res;
}

async function send(
  peerDid: string,
  endpoint: string,
  text: string,
  options: { attachProvenanceHash?: string; provenanceUrl?: string } = {},
): Promise<void> {
  const identity = loadOrCreateIdentity();
  await sendMessage(identity, peerDid, endpoint, text, options);
  console.log(`sent to ${peerDid} via ${endpoint}`);
}

/**
 * Unpacks an inbound envelope and extracts its chat content plus any
 * provenance attachment references, logging exactly what `listen` has
 * always logged on receipt. Shared by `listen` and `serve`'s receiver
 * callback so both go through one code path.
 */
async function unpackAndLog(
  envelopeBytes: Uint8Array,
  resolvers: { did: DidResolver; secrets: SecretsResolver },
): Promise<{ message: CorePlaintextMessage; senderKey: string | null; content: string }> {
  const { message, senderKey } = await unpack(envelopeBytes, resolvers);
  const content = (message.body as { content?: string } | undefined)?.content ?? "<non-chat message>";
  console.log(`[${senderKey ?? message.from ?? "unknown"}] ${content}`);

  const attachments = (message as { attachments?: unknown }).attachments;
  if (Array.isArray(attachments)) {
    for (const attachment of attachments) {
      if (typeof attachment !== "object" || attachment === null) continue;
      const ref = readProvenance(
        attachment as { id: string; data: { base64?: string; json?: unknown; links?: string[] } },
      );
      if (!ref) continue;
      const id = (attachment as { id?: unknown }).id;
      console.log(
        `[provenance] attachment ${typeof id === "string" ? id : "?"}: sha256:${ref.hash.value} (${ref.url ?? "embedded"})`,
      );
    }
  }

  return { message, senderKey, content };
}

async function listen(port: number): Promise<void> {
  const identity = loadOrCreateIdentity();
  const did = combinedResolver(identity);
  const secrets = identitySecretsResolver(identity);

  const { port: boundPort } = await listenHttp(port, async (envelopeBytes) => {
    await unpackAndLog(envelopeBytes, { did, secrets });
  });

  console.log(`identity: ${identity.did}`);
  console.log(`listening on port ${boundPort}`);
}

/** A chat log entry shown in the web UI, kept in-memory by `serve`. */
interface ChatLogEntry {
  direction: "sent" | "received";
  peerDid: string;
  text: string;
  timestamp: number;
}

const CHAT_LOG_LIMIT = 200;

function pushChatLogEntry(log: ChatLogEntry[], entry: ChatLogEntry): void {
  log.push(entry);
  if (log.length > CHAT_LOG_LIMIT) log.splice(0, log.length - CHAT_LOG_LIMIT);
}

/**
 * Builds the `serve` subcommand's Express app: the real DIDComm envelope
 * receiver (`POST /`, from `createHttpReceiver`, unmodified), three JSON
 * API routes for the web chat UI, and the static chat page itself. Kept
 * separate from `serve()` so it can be exercised without binding a port.
 */
function buildServeApp(identity: Identity): Express {
  const did = combinedResolver(identity);
  const secrets = identitySecretsResolver(identity);
  const chatLog: ChatLogEntry[] = [];

  const app = createHttpReceiver(async (envelopeBytes) => {
    const { message, senderKey } = await unpackAndLog(envelopeBytes, { did, secrets });
    const peerDid = message.from ?? senderKey?.split("#")[0] ?? "unknown";
    const content = (message.body as { content?: string } | undefined)?.content ?? "<non-chat message>";
    pushChatLogEntry(chatLog, { direction: "received", peerDid, text: content, timestamp: Date.now() });
  });

  app.use("/api", express.json());

  app.get("/api/identity", (_req, res) => {
    res.json({ did: identity.did });
  });

  app.get("/api/messages", (_req, res) => {
    res.json(chatLog);
  });

  app.post("/api/send", (req, res) => {
    const body = req.body as { peerDid?: unknown; endpoint?: unknown; text?: unknown };
    const { peerDid, endpoint, text } = body;
    if (typeof peerDid !== "string" || !peerDid) {
      res.status(400).json({ error: "peerDid is required" });
      return;
    }
    if (typeof endpoint !== "string" || !endpoint) {
      res.status(400).json({ error: "endpoint is required" });
      return;
    }
    if (typeof text !== "string" || !text) {
      res.status(400).json({ error: "text is required" });
      return;
    }

    void sendMessage(identity, peerDid, endpoint, text)
      .then((sendRes) => {
        if (!sendRes.ok) {
          res.status(502).json({ error: `peer responded ${sendRes.status}` });
          return;
        }
        pushChatLogEntry(chatLog, { direction: "sent", peerDid, text, timestamp: Date.now() });
        res.json({ ok: true });
      })
      .catch((err: unknown) => {
        res.status(502).json({ error: err instanceof Error ? err.message : String(err) });
      });
  });

  const publicDir = fileURLToPath(new URL("./public", import.meta.url));
  app.use(express.static(publicDir));

  return app;
}

async function serve(port: number): Promise<void> {
  const identity = loadOrCreateIdentity();
  const app = buildServeApp(identity);

  await new Promise<void>((resolve, reject) => {
    const server = app.listen(port);
    server.once("error", reject);
    server.once("listening", () => {
      const address = server.address();
      const boundPort = typeof address === "object" && address !== null ? address.port : port;
      console.log(`identity: ${identity.did}`);
      console.log(`chat UI listening on port ${boundPort}`);
      resolve();
    });
  });
}

/**
 * Requests mediation from `mediatorDid` (DIDComm Coordinate Mediation,
 * version auto-discovered via discover-features — 2.0 or 3.0: mediate-request
 * → mediate-grant) and registers this identity's own DID as a recipient
 * (keylist-update in 2.0 / recipient-update in 3.0, action "add"). Prints
 * the mediator's granted routing DID(s), which should be used as
 * `routingKeys` entries when publishing this identity's own service
 * endpoint for others to reach it through this mediator.
 */
async function mediate(mediatorDid: string): Promise<void> {
  const identity = loadOrCreateIdentity();
  const did = combinedResolver(identity);
  const secrets = identitySecretsResolver(identity);
  const ctx = { selfDid: identity.did, did, secrets };

  const grant = await requestMediation(mediatorDid, ctx);
  console.log(`mediation granted; routing_did(s): ${grant.routingDids.join(", ")}`);

  const recipientResult = await updateRecipient(mediatorDid, identity.did, "add", ctx);
  console.log(`recipient-update: ${recipientResult.result} (${identity.did})`);

  const mediatorEndpoint = await resolveDirectEndpoint(mediatorDid, did);
  const publicKeyBase64Url = (identity.secretJwk as { x?: string }).x;
  if (publicKeyBase64Url) {
    const peerDid = buildDidPeer2(publicKeyBase64Url, mediatorEndpoint, grant.routingDids);
    console.log(`reachable at: ${peerDid}`);
  }
}

/** Retrieves and prints all messages currently queued at `mediatorDid`, then acknowledges them. */
async function pickup(mediatorDid: string): Promise<void> {
  const identity = loadOrCreateIdentity();
  const did = combinedResolver(identity);
  const secrets = identitySecretsResolver(identity);
  const ctx = { selfDid: identity.did, did, secrets };

  const status = await requestStatus(mediatorDid, ctx);
  console.log(`messages queued: ${status.messageCount}`);
  if (status.messageCount === 0) return;

  const delivered = await requestDelivery(mediatorDid, ctx, status.messageCount);
  for (const { envelopeBytes } of delivered) {
    const { message, senderKey } = await unpack(envelopeBytes, { did, secrets });
    const content = (message.body as { content?: string } | undefined)?.content ?? "<non-chat message>";
    console.log(`[${senderKey ?? message.from ?? "unknown"}] ${content}`);
  }

  const result = await acknowledgeReceived(mediatorDid, ctx, delivered.map((d) => d.attachmentId));
  console.log(`acknowledged; messages still queued: ${result.messageCount}`);
}

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2);

  switch (cmd) {
    case "send": {
      const parsed = parseSendArgs(rest);
      if (!parsed) usage();
      await send(parsed.peerDid, parsed.endpoint, parsed.text, {
        attachProvenanceHash: parsed.attachProvenanceHash,
        provenanceUrl: parsed.provenanceUrl,
      });
      return;
    }
    case "listen": {
      const port = rest[0] ? Number(rest[0]) : Number(process.env.PORT) || DEFAULT_PORT;
      await listen(port);
      return;
    }
    case "serve": {
      const port = rest[0] ? Number(rest[0]) : Number(process.env.PORT) || DEFAULT_PORT;
      await serve(port);
      return;
    }
    case "mediate": {
      const [mediatorDid] = rest;
      if (!mediatorDid) usage();
      await mediate(mediatorDid);
      return;
    }
    case "pickup": {
      const [mediatorDid] = rest;
      if (!mediatorDid) usage();
      await pickup(mediatorDid);
      return;
    }
    default:
      usage();
  }
}

const isMain = process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  main().catch((err: unknown) => {
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(1);
  });
}
