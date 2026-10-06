import { randomUUID } from "node:crypto";
import type { PlaintextMessage } from "../core/index.js";
import { resolveDirectEndpoint, sendAndAwaitReply, type RpcContext } from "./didcommRpc.js";

/**
 * Client for the DIDComm Message Pickup Protocol 3.0
 * (https://didcomm.org/messagepickup/3.0/): querying how many messages a
 * mediator is holding for this identity, retrieving a batch of them, and
 * acknowledging receipt so the mediator clears them from its queue.
 */

const STATUS_REQUEST_TYPE = "https://didcomm.org/messagepickup/3.0/status-request";
const STATUS_TYPE = "https://didcomm.org/messagepickup/3.0/status";
const DELIVERY_REQUEST_TYPE = "https://didcomm.org/messagepickup/3.0/delivery-request";
const DELIVERY_TYPE = "https://didcomm.org/messagepickup/3.0/delivery";
const MESSAGES_RECEIVED_TYPE = "https://didcomm.org/messagepickup/3.0/messages-received";

export interface PickupStatus {
  messageCount: number;
  liveDelivery?: boolean;
  longestWaitedSeconds?: number;
}

export interface DeliveredMessage {
  /** The mediator's id for this queued message — pass back via `acknowledgeReceived` to clear it. */
  attachmentId: string;
  /** The raw (still-encrypted) envelope bytes, decoded from the attachment's base64 `data`. */
  envelopeBytes: Uint8Array;
}

function basePlaintext(type: string, body: unknown, from: string, to: string): PlaintextMessage {
  return { id: randomUUID(), typ: "application/didcomm-plain+json", type, body, from, to: [to], return_route: "all" };
}

/** Queries `mediatorDid` for how many messages it's holding for this identity. */
export async function requestStatus(mediatorDid: string, ctx: RpcContext): Promise<PickupStatus> {
  const endpoint = await resolveDirectEndpoint(mediatorDid, ctx.did);
  const request = basePlaintext(STATUS_REQUEST_TYPE, {}, ctx.selfDid, mediatorDid);
  const reply = await sendAndAwaitReply(request, mediatorDid, endpoint, ctx);

  if (reply.type !== STATUS_TYPE) {
    throw new Error(`unexpected reply type from ${mediatorDid}: ${reply.type}`);
  }
  const body = reply.body as
    | { message_count?: number; live_delivery?: boolean; longest_waited_seconds?: number }
    | undefined;
  if (typeof body?.message_count !== "number") {
    throw new Error(`status reply from ${mediatorDid} is missing body.message_count`);
  }
  return {
    messageCount: body.message_count,
    liveDelivery: body.live_delivery,
    longestWaitedSeconds: body.longest_waited_seconds,
  };
}

/** Retrieves up to `limit` queued messages from `mediatorDid`, as still-encrypted envelope bytes. */
export async function requestDelivery(
  mediatorDid: string,
  ctx: RpcContext,
  limit: number,
): Promise<DeliveredMessage[]> {
  const endpoint = await resolveDirectEndpoint(mediatorDid, ctx.did);
  const request = basePlaintext(DELIVERY_REQUEST_TYPE, { limit }, ctx.selfDid, mediatorDid);
  const reply = await sendAndAwaitReply(request, mediatorDid, endpoint, ctx);

  if (reply.type !== DELIVERY_TYPE) {
    throw new Error(`unexpected reply type from ${mediatorDid}: ${reply.type}`);
  }
  const attachments = (
    reply as { attachments?: { id: string; data: { base64?: string } }[] }
  ).attachments ?? [];
  return attachments.map((attachment) => {
    if (!attachment.data.base64) {
      throw new Error(`delivery attachment ${attachment.id} from ${mediatorDid} has no base64 data`);
    }
    return { attachmentId: attachment.id, envelopeBytes: Buffer.from(attachment.data.base64, "base64") };
  });
}

/** Acknowledges receipt of `attachmentIds`, so `mediatorDid` clears them from its queue. */
export async function acknowledgeReceived(
  mediatorDid: string,
  ctx: RpcContext,
  attachmentIds: string[],
): Promise<PickupStatus> {
  const endpoint = await resolveDirectEndpoint(mediatorDid, ctx.did);
  const request = basePlaintext(
    MESSAGES_RECEIVED_TYPE,
    { message_id_list: attachmentIds },
    ctx.selfDid,
    mediatorDid,
  );
  const reply = await sendAndAwaitReply(request, mediatorDid, endpoint, ctx);

  if (reply.type !== STATUS_TYPE) {
    throw new Error(`unexpected reply type from ${mediatorDid}: ${reply.type}`);
  }
  const body = reply.body as { message_count?: number } | undefined;
  if (typeof body?.message_count !== "number") {
    throw new Error(`status reply from ${mediatorDid} is missing body.message_count`);
  }
  return { messageCount: body.message_count };
}
