import { randomUUID } from "node:crypto";
import {
  packAuthcrypt,
  unpack,
  type DidResolver,
  type PlaintextMessage,
  type SecretsResolver,
} from "../core/index.js";
import { selectRoutingPath, type DIDDoc as RoutingDIDDoc } from "../routing/index.js";
import { sendHttp } from "../transport/index.js";

/**
 * Client for the DIDComm Mediator Coordination Protocol 2.0
 * (https://didcomm.org/coordinate-mediation/2.0/): requesting mediation from
 * a mediator and registering/removing recipient keys in its keylist. Message
 * type URIs and body shapes are taken directly from that spec.
 */

const MEDIATE_REQUEST_TYPE = "https://didcomm.org/coordinate-mediation/2.0/mediate-request";
const MEDIATE_GRANT_TYPE = "https://didcomm.org/coordinate-mediation/2.0/mediate-grant";
const MEDIATE_DENY_TYPE = "https://didcomm.org/coordinate-mediation/2.0/mediate-deny";
const KEYLIST_UPDATE_TYPE = "https://didcomm.org/coordinate-mediation/2.0/keylist-update";
const KEYLIST_UPDATE_RESPONSE_TYPE =
  "https://didcomm.org/coordinate-mediation/2.0/keylist-update-response";

export interface MediationContext {
  /** This party's own DID (the mediation client / future routing recipient). */
  selfDid: string;
  did: DidResolver;
  secrets: SecretsResolver;
}

export interface MediationGrant {
  /** The mediator's routing DID — the recipient uses this as a `routingKeys` entry in its own service. */
  routingDid: string;
}

export interface KeylistUpdateResult {
  recipientDid: string;
  action: "add" | "remove";
  result: "client_error" | "server_error" | "no_change" | "success";
}

function basePlaintext(type: string, body: unknown, from: string, to: string): PlaintextMessage {
  return {
    id: randomUUID(),
    typ: "application/didcomm-plain+json",
    type,
    body,
    from,
    to: [to],
    return_route: "all",
  };
}

/**
 * Resolves `did`'s direct (zero-mediator) HTTP endpoint via its DIDDoc's
 * `DIDCommMessaging` service entry. Mediators are expected to publish a
 * directly reachable endpoint (no routingKeys of their own).
 */
async function resolveDirectEndpoint(did: string, resolver: DidResolver): Promise<string> {
  const doc = await resolver.resolve(did);
  if (!doc) throw new Error(`could not resolve DID: ${did}`);
  const routingDoc = { id: doc.id, service: doc.service } as unknown as RoutingDIDDoc;
  const paths = selectRoutingPath(routingDoc);
  const direct = paths.find((path) => path.mediators.length === 0);
  if (!direct) {
    throw new Error(`no directly reachable DIDCommMessaging service endpoint found for ${did}`);
  }
  return direct.endpoint;
}

/** Packs `plaintext` as authcrypt to `mediatorDid`, POSTs it, and unpacks the mediator's synchronous reply. */
async function sendAndAwaitReply(
  plaintext: PlaintextMessage,
  mediatorDid: string,
  endpoint: string,
  ctx: MediationContext,
): Promise<PlaintextMessage> {
  const envelope = await packAuthcrypt(plaintext, [mediatorDid], ctx.selfDid, {
    did: ctx.did,
    secrets: ctx.secrets,
  });
  const bytes = typeof envelope === "string" ? new TextEncoder().encode(envelope) : envelope;

  const response = await sendHttp(endpoint, bytes, "application/didcomm-encrypted+json");
  const replyBytes = new Uint8Array(await response.arrayBuffer());
  if (replyBytes.length === 0) {
    throw new Error(
      `mediator ${mediatorDid} returned no synchronous reply body (HTTP ${response.status}); ` +
        "this client requires return_route: all support",
    );
  }

  const { message } = await unpack(replyBytes, { did: ctx.did, secrets: ctx.secrets });
  return message;
}

/** Sends `mediate-request` to `mediatorDid` and returns its granted routing DID, or throws on `mediate-deny`. */
export async function requestMediation(
  mediatorDid: string,
  ctx: MediationContext,
): Promise<MediationGrant> {
  const endpoint = await resolveDirectEndpoint(mediatorDid, ctx.did);
  const request = basePlaintext(MEDIATE_REQUEST_TYPE, {}, ctx.selfDid, mediatorDid);

  const reply = await sendAndAwaitReply(request, mediatorDid, endpoint, ctx);

  if (reply.type === MEDIATE_DENY_TYPE) {
    throw new Error(`mediator ${mediatorDid} denied the mediation request`);
  }
  if (reply.type !== MEDIATE_GRANT_TYPE) {
    throw new Error(`unexpected reply type from ${mediatorDid}: ${reply.type}`);
  }

  const routingDid = (reply.body as { routing_did?: string } | undefined)?.routing_did;
  if (!routingDid) {
    throw new Error(`mediate-grant from ${mediatorDid} is missing body.routing_did`);
  }
  return { routingDid };
}

/** Adds or removes `recipientDid` in `mediatorDid`'s keylist via `keylist-update`. */
export async function updateKeylist(
  mediatorDid: string,
  recipientDid: string,
  action: "add" | "remove",
  ctx: MediationContext,
): Promise<KeylistUpdateResult> {
  const endpoint = await resolveDirectEndpoint(mediatorDid, ctx.did);
  const request = basePlaintext(
    KEYLIST_UPDATE_TYPE,
    { updates: [{ recipient_did: recipientDid, action }] },
    ctx.selfDid,
    mediatorDid,
  );

  const reply = await sendAndAwaitReply(request, mediatorDid, endpoint, ctx);

  if (reply.type !== KEYLIST_UPDATE_RESPONSE_TYPE) {
    throw new Error(`unexpected reply type from ${mediatorDid}: ${reply.type}`);
  }

  const updated = (
    reply.body as {
      updated?: { recipient_did: string; action: "add" | "remove"; result: KeylistUpdateResult["result"] }[];
    }
  )?.updated;
  const entry = updated?.find((item) => item.recipient_did === recipientDid && item.action === action);
  if (!entry) {
    throw new Error(`keylist-update-response from ${mediatorDid} did not confirm ${action} for ${recipientDid}`);
  }
  if (entry.result !== "success" && entry.result !== "no_change") {
    throw new Error(`keylist-update for ${recipientDid} failed: ${entry.result}`);
  }
  return { recipientDid, action, result: entry.result };
}
