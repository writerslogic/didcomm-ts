#!/usr/bin/env node
/**
 * Minimal CLI chat demo over generic DIDComm v2.
 *
 * Usage:
 *   node dist/chat/cli.js send <peer-did> <endpoint-url> <text...>
 *   node dist/chat/cli.js listen [port]
 *
 * Peer DIDs must be the `did:key` form this package's own identities use
 * (a bare X25519 key-agreement key, see keys.ts) — there is no DID network
 * resolver here, so an explicit transport endpoint is passed on the command
 * line rather than discovered from a DIDComm service entry.
 */
import { randomUUID } from "node:crypto";
import { pathToFileURL } from "node:url";
import { didKeyFragment, didKeyToX25519PublicJwk, loadOrCreateIdentity, type Identity } from "./keys.js";
import {
  packAuthcrypt,
  unpack,
  type DIDDoc,
  type DidResolver,
  type SecretsResolver,
} from "../core/index.js";
import { sendHttp, listenHttp } from "../transport/index.js";

/** Basic-message protocol URI (generic DIDComm v2, not interop-partner specific). */
const BASIC_MESSAGE_TYPE = "https://didcomm.org/basicmessage/2.0/message";
const DEFAULT_PORT = 8787;

function usage(): never {
  console.error("usage:\n  chat send <peer-did> <endpoint-url> <text...>\n  chat listen [port]");
  process.exit(1);
}

/** Builds a did:key DIDDoc with a single keyAgreement verification method. */
function didKeyDoc(did: string): DIDDoc {
  const kid = didKeyFragment(did);
  return {
    id: did,
    keyAgreement: [kid],
    authentication: [],
    verificationMethod: [
      { id: kid, type: "X25519KeyAgreementKey2020", controller: did, publicKeyJwk: didKeyToX25519PublicJwk(did) },
    ],
    service: [],
  };
}

/** A DidResolver that resolves only the local identity's own DID and `did:key` peers. */
function didKeyResolver(identity: Identity): DidResolver {
  const ownDoc = didKeyDoc(identity.did);
  return {
    async resolve(did: string): Promise<DIDDoc | null> {
      if (did === identity.did) return ownDoc;
      try {
        return didKeyDoc(did);
      } catch {
        return null;
      }
    },
  };
}

/** A SecretsResolver backed by the local identity's one X25519 secret. */
function identitySecretsResolver(identity: Identity): SecretsResolver {
  const kid = didKeyFragment(identity.did);
  const secret = { id: kid, type: "X25519KeyAgreementKey2020", privateKeyJwk: identity.secretJwk };
  return {
    async get_secret(secretId: string) {
      return secretId === kid ? secret : null;
    },
    async find_secrets(secretIds: string[]) {
      return secretIds.includes(kid) ? [kid] : [];
    },
  };
}

async function send(peerDid: string, endpoint: string, text: string): Promise<void> {
  const identity = loadOrCreateIdentity();
  const did = didKeyResolver(identity);
  const secrets = identitySecretsResolver(identity);

  const envelope = await packAuthcrypt(
    {
      id: randomUUID(),
      typ: "application/didcomm-plain+json",
      type: BASIC_MESSAGE_TYPE,
      body: { content: text },
      from: identity.did,
      to: [peerDid],
    },
    [peerDid],
    identity.did,
    { did, secrets },
  );

  const bytes = typeof envelope === "string" ? new TextEncoder().encode(envelope) : envelope;
  await sendHttp(endpoint, bytes, "application/didcomm-encrypted+json");
  console.log(`sent to ${peerDid} via ${endpoint}`);
}

async function listen(port: number): Promise<void> {
  const identity = loadOrCreateIdentity();
  const did = didKeyResolver(identity);
  const secrets = identitySecretsResolver(identity);

  const { port: boundPort } = await listenHttp(port, async (envelopeBytes) => {
    const { message, senderKey } = await unpack(envelopeBytes, { did, secrets });
    const content = (message.body as { content?: string } | undefined)?.content ?? "<non-chat message>";
    console.log(`[${senderKey ?? message.from ?? "unknown"}] ${content}`);
  });

  console.log(`identity: ${identity.did}`);
  console.log(`listening on port ${boundPort}`);
}

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2);

  switch (cmd) {
    case "send": {
      const [peerDid, endpoint, ...words] = rest;
      if (!peerDid || !endpoint || words.length === 0) usage();
      await send(peerDid, endpoint, words.join(" "));
      return;
    }
    case "listen": {
      const port = rest[0] ? Number(rest[0]) : DEFAULT_PORT;
      await listen(port);
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
