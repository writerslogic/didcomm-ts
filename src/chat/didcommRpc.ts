import type {
  DidResolver,
  PlaintextMessage,
  SecretsResolver,
  packAuthcrypt,
  unpack,
} from "../core/index.js";
import { selectRoutingPath, type DIDDoc as RoutingDIDDoc } from "../routing/index.js";
import { sendHttp } from "../transport/index.js";

/** The pack/unpack pair an exchange uses: the WASM core or `core/pure`. */
export interface EnvelopeBackend {
  packAuthcrypt: typeof packAuthcrypt;
  unpack: typeof unpack;
}

/** Shared context for a synchronous (`return_route: all`) request/reply exchange with a DIDComm service. */
export interface RpcContext {
  /** This party's own DID. */
  selfDid: string;
  did: DidResolver;
  secrets: SecretsResolver;
  /** Envelope implementation. Default: the didcomm-rust (WASM) core. */
  backend?: EnvelopeBackend;
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
  // Loaded on demand so a context using `core/pure` never loads the WASM core.
  const backend = ctx.backend ?? (await import("../core/index.js"));
  const envelope = await backend.packAuthcrypt(plaintext, [targetDid], ctx.selfDid, {
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

  const { message } = await backend.unpack(replyBytes, { did: ctx.did, secrets: ctx.secrets });
  return message;
}
