import {
  packAuthcrypt,
  unpack,
  type DidResolver,
  type PlaintextMessage,
  type SecretsResolver,
} from "../core/index.js";
import { selectRoutingPath, type DIDDoc as RoutingDIDDoc } from "../routing/index.js";
import { sendHttp } from "../transport/index.js";

/** Shared context for a synchronous (`return_route: all`) request/reply exchange with a DIDComm service. */
export interface RpcContext {
  /** This party's own DID. */
  selfDid: string;
  did: DidResolver;
  secrets: SecretsResolver;
}

/**
 * Resolves `did`'s direct (zero-mediator) HTTP endpoint via its DIDDoc's
 * `DIDCommMessaging` service entry. Mediators are expected to publish a
 * directly reachable endpoint (no routingKeys of their own).
 */
export async function resolveDirectEndpoint(did: string, resolver: DidResolver): Promise<string> {
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

/** Packs `plaintext` as authcrypt to `targetDid`, POSTs it to `endpoint`, and unpacks the synchronous reply. */
export async function sendAndAwaitReply(
  plaintext: PlaintextMessage,
  targetDid: string,
  endpoint: string,
  ctx: RpcContext,
): Promise<PlaintextMessage> {
  const envelope = await packAuthcrypt(plaintext, [targetDid], ctx.selfDid, {
    did: ctx.did,
    secrets: ctx.secrets,
  });
  const bytes = typeof envelope === "string" ? new TextEncoder().encode(envelope) : envelope;

  const response = await sendHttp(endpoint, bytes, "application/didcomm-encrypted+json");
  const replyBytes = new Uint8Array(await response.arrayBuffer());
  if (replyBytes.length === 0) {
    throw new Error(
      `${targetDid} returned no synchronous reply body (HTTP ${response.status}); ` +
        "this client requires return_route: all support",
    );
  }

  const { message } = await unpack(replyBytes, { did: ctx.did, secrets: ctx.secrets });
  return message;
}
