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
 * Client for the DIDComm Mediator Coordination Protocol, versions 2.0
 * (https://didcomm.org/coordinate-mediation/2.0/) and 3.0
 * (https://didcomm.org/coordinate-mediation/3.0/). The two versions differ
 * in message type names and one body shape:
 *   - 2.0: `keylist-update` / `keylist-update-response` / `keylist-query` /
 *     `keylist`; `mediate-grant.body.routing_did` is a single string.
 *   - 3.0: `recipient-update` / `recipient-update-response` /
 *     `recipient-query` / `recipient`; `mediate-grant.body.routing_did` is
 *     an ARRAY of strings (one routing DID per mediator-side device/path —
 *     verified against the real reply from mediator.wyvrn.app, which only
 *     discloses 3.0 via `discover-features/2.0` and rejects 2.0 message
 *     types with a `report-problem` "unsupported message type").
 * `mediate-request`/`mediate-grant`/`mediate-deny` message type names and
 * bodies are identical across both versions.
 *
 * Which version a given mediator speaks isn't knowable in advance, so
 * `discoverMediationVersion` queries it via the standard
 * `discover-features/2.0` protocol rather than guessing.
 */

export type MediationProtocolVersion = "2.0" | "3.0";

export interface MediationContext {
  /** This party's own DID (the mediation client / future routing recipient). */
  selfDid: string;
  did: DidResolver;
  secrets: SecretsResolver;
}

export interface MediationGrant {
  /**
   * The mediator's granted routing DID(s) — each becomes a `routingKeys`
   * entry in this identity's own published service. Always an array, even
   * against a 2.0 mediator (whose single `routing_did` is wrapped in one).
   */
  routingDids: string[];
}

export interface RecipientUpdateResult {
  recipientDid: string;
  action: "add" | "remove";
  result: "client_error" | "server_error" | "no_change" | "success";
}

const MEDIATE_REQUEST_TYPE = (v: MediationProtocolVersion) =>
  `https://didcomm.org/coordinate-mediation/${v}/mediate-request`;
const MEDIATE_GRANT_TYPE = (v: MediationProtocolVersion) =>
  `https://didcomm.org/coordinate-mediation/${v}/mediate-grant`;
const MEDIATE_DENY_TYPE = (v: MediationProtocolVersion) =>
  `https://didcomm.org/coordinate-mediation/${v}/mediate-deny`;
/** 2.0 calls this "keylist-update"/"keylist-update-response"; 3.0 renames it "recipient-update"/"...-response". */
const RECIPIENT_UPDATE_TYPE = (v: MediationProtocolVersion) =>
  v === "2.0"
    ? "https://didcomm.org/coordinate-mediation/2.0/keylist-update"
    : "https://didcomm.org/coordinate-mediation/3.0/recipient-update";
const RECIPIENT_UPDATE_RESPONSE_TYPE = (v: MediationProtocolVersion) =>
  v === "2.0"
    ? "https://didcomm.org/coordinate-mediation/2.0/keylist-update-response"
    : "https://didcomm.org/coordinate-mediation/3.0/recipient-update-response";

const DISCOVER_FEATURES_QUERIES_TYPE = "https://didcomm.org/discover-features/2.0/queries";
const DISCOVER_FEATURES_DISCLOSE_TYPES = [
  "https://didcomm.org/discover-features/2.0/disclose",
  "https://didcomm.org/discover-features/2.0/disclosures",
];

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

/**
 * Queries `mediatorDid` via `discover-features/2.0` for which
 * `coordinate-mediation` protocol version it supports, preferring 3.0 if
 * both are disclosed. Throws if neither is disclosed.
 */
export async function discoverMediationVersion(
  mediatorDid: string,
  ctx: MediationContext,
): Promise<MediationProtocolVersion> {
  const endpoint = await resolveDirectEndpoint(mediatorDid, ctx.did);
  const request = basePlaintext(
    DISCOVER_FEATURES_QUERIES_TYPE,
    { queries: [{ "feature-type": "protocol", match: "https://didcomm.org/coordinate-mediation/*" }] },
    ctx.selfDid,
    mediatorDid,
  );

  const reply = await sendAndAwaitReply(request, mediatorDid, endpoint, ctx);
  if (!DISCOVER_FEATURES_DISCLOSE_TYPES.includes(reply.type)) {
    throw new Error(`unexpected reply type from ${mediatorDid}: ${reply.type}`);
  }

  const disclosures =
    (reply.body as { disclosures?: { id?: string }[] } | undefined)?.disclosures ?? [];
  const ids = new Set(disclosures.map((d) => d.id));
  if (ids.has("https://didcomm.org/coordinate-mediation/3.0")) return "3.0";
  if (ids.has("https://didcomm.org/coordinate-mediation/2.0")) return "2.0";
  throw new Error(`${mediatorDid} did not disclose support for coordinate-mediation 2.0 or 3.0`);
}

/**
 * Sends `mediate-request` to `mediatorDid` and returns its granted routing
 * DID(s), or throws on `mediate-deny`. `version` is auto-discovered via
 * `discoverMediationVersion` when omitted.
 */
export async function requestMediation(
  mediatorDid: string,
  ctx: MediationContext,
  version?: MediationProtocolVersion,
): Promise<MediationGrant> {
  const v = version ?? (await discoverMediationVersion(mediatorDid, ctx));
  const endpoint = await resolveDirectEndpoint(mediatorDid, ctx.did);
  const request = basePlaintext(MEDIATE_REQUEST_TYPE(v), {}, ctx.selfDid, mediatorDid);

  const reply = await sendAndAwaitReply(request, mediatorDid, endpoint, ctx);

  if (reply.type === MEDIATE_DENY_TYPE(v)) {
    throw new Error(`mediator ${mediatorDid} denied the mediation request`);
  }
  if (reply.type !== MEDIATE_GRANT_TYPE(v)) {
    throw new Error(`unexpected reply type from ${mediatorDid}: ${reply.type}`);
  }

  const routingDid = (reply.body as { routing_did?: string | string[] } | undefined)?.routing_did;
  if (!routingDid) {
    throw new Error(`mediate-grant from ${mediatorDid} is missing body.routing_did`);
  }
  return { routingDids: Array.isArray(routingDid) ? routingDid : [routingDid] };
}

/**
 * Adds or removes `recipientDid` in `mediatorDid`'s recipient list
 * (`keylist-update` in 2.0, `recipient-update` in 3.0). `version` is
 * auto-discovered via `discoverMediationVersion` when omitted.
 */
export async function updateRecipient(
  mediatorDid: string,
  recipientDid: string,
  action: "add" | "remove",
  ctx: MediationContext,
  version?: MediationProtocolVersion,
): Promise<RecipientUpdateResult> {
  const v = version ?? (await discoverMediationVersion(mediatorDid, ctx));
  const endpoint = await resolveDirectEndpoint(mediatorDid, ctx.did);
  const request = basePlaintext(
    RECIPIENT_UPDATE_TYPE(v),
    { updates: [{ recipient_did: recipientDid, action }] },
    ctx.selfDid,
    mediatorDid,
  );

  const reply = await sendAndAwaitReply(request, mediatorDid, endpoint, ctx);

  if (reply.type !== RECIPIENT_UPDATE_RESPONSE_TYPE(v)) {
    throw new Error(`unexpected reply type from ${mediatorDid}: ${reply.type}`);
  }

  const updated = (
    reply.body as {
      updated?: { recipient_did: string; action: "add" | "remove"; result: RecipientUpdateResult["result"] }[];
    }
  )?.updated;
  const entry = updated?.find((item) => item.recipient_did === recipientDid && item.action === action);
  if (!entry) {
    throw new Error(`recipient-update-response from ${mediatorDid} did not confirm ${action} for ${recipientDid}`);
  }
  if (entry.result !== "success" && entry.result !== "no_change") {
    throw new Error(`recipient-update for ${recipientDid} failed: ${entry.result}`);
  }
  return { recipientDid, action, result: entry.result };
}
