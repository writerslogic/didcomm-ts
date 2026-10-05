import { randomUUID } from 'node:crypto';

/** DIDComm Messaging v2 forward message type URI. */
export const FORWARD_MESSAGE_TYPE = 'https://didcomm.org/routing/2.0/forward';

/**
 * A DIDComm plaintext message. Only the fields routing cares about are
 * typed explicitly; arbitrary additional fields are preserved untouched.
 */
export interface PlaintextMessage {
  id: string;
  type: string;
  body: Record<string, unknown>;
  to?: string[];
  from?: string;
  attachments?: Attachment[];
  [key: string]: unknown;
}

export interface AttachmentData {
  json?: unknown;
  base64?: string;
  links?: string[];
  jws?: unknown;
}

export interface Attachment {
  id: string;
  description?: string;
  media_type?: string;
  format?: string;
  data: AttachmentData;
}

export interface ForwardBody {
  next: string;
  [key: string]: unknown;
}

/**
 * An anoncrypted DIDComm message (JWE-shaped). Its concrete shape is owned
 * by whichever crypto layer produces/consumes it; routing treats it as
 * opaque ciphertext that gets carried as a forward attachment.
 */
export type EncryptedMessage = Record<string, unknown>;

/**
 * Crypto dependency injected into the routing layer so forward.ts stays
 * free of key-management/crypto concerns. `recipientKeyId` is whatever
 * identifier the crypto layer needs to resolve the mediator's anoncrypt
 * key (a DID, a DID URL key id, etc.).
 */
export interface AnoncryptProvider {
  encrypt(
    message: PlaintextMessage,
    recipientKeyId: string,
  ): Promise<EncryptedMessage> | EncryptedMessage;
  decrypt(message: EncryptedMessage): Promise<PlaintextMessage> | PlaintextMessage;
}

export interface WrapInForwardOptions {
  /** Override the generated forward message's `id`. */
  id?: string;
  /** Override the generated attachment's `id`. */
  attachmentId?: string;
}

/**
 * Wraps an already-encrypted DIDComm message in a forward message
 * (type https://didcomm.org/routing/2.0/forward) addressed to `next`,
 * carrying the original message as a JSON attachment, then anoncrypts
 * the forward message to the mediator identified by `recipientKeyId`.
 */
export async function wrapInForward(
  message: EncryptedMessage,
  next: string,
  recipientKeyId: string,
  crypto: AnoncryptProvider,
  options: WrapInForwardOptions = {},
): Promise<EncryptedMessage> {
  const attachment: Attachment = {
    id: options.attachmentId ?? randomUUID(),
    media_type: 'application/json',
    data: { json: message },
  };

  const forwardBody: ForwardBody = { next };

  const forwardMessage: PlaintextMessage = {
    id: options.id ?? randomUUID(),
    type: FORWARD_MESSAGE_TYPE,
    to: [next],
    body: forwardBody,
    attachments: [attachment],
  };

  return crypto.encrypt(forwardMessage, recipientKeyId);
}

/**
 * Wraps `message` through an ordered chain of mediators, innermost first.
 * `mediators[0]` is the mediator closest to the final recipient (so it is
 * wrapped first, with `next` set to `finalRecipient`); each subsequent
 * mediator wraps the previous forward message, with `next` set to the
 * previous mediator. The result is addressed to `mediators[mediators.length - 1]`
 * and is what gets transmitted to that mediator's service endpoint.
 */
export async function wrapForwardChain(
  message: EncryptedMessage,
  mediators: readonly string[],
  finalRecipient: string,
  crypto: AnoncryptProvider,
): Promise<EncryptedMessage> {
  let current = message;
  let next = finalRecipient;

  for (const mediatorKeyId of mediators) {
    current = await wrapInForward(current, next, mediatorKeyId, crypto);
    next = mediatorKeyId;
  }

  return current;
}

export interface UnwrappedForward {
  /** The DID (or key id) the attached message should be forwarded to next. */
  next: string;
  /** The attached (still encrypted) message to forward. */
  attachedMessage: EncryptedMessage;
}

/**
 * Extracts the `next` recipient and the inner attached message from a
 * decrypted forward message. This is the mediator-side counterpart of
 * {@link wrapInForward}; the caller is responsible for anondecrypting the
 * message beforehand (e.g. via an {@link AnoncryptProvider}).
 */
export function unwrapForward(message: PlaintextMessage): UnwrappedForward {
  if (message.type !== FORWARD_MESSAGE_TYPE) {
    throw new Error(
      `unwrapForward: expected message type "${FORWARD_MESSAGE_TYPE}", got "${message.type}"`,
    );
  }

  const next = (message.body as Partial<ForwardBody> | undefined)?.next;
  if (typeof next !== 'string' || next.length === 0) {
    throw new Error('unwrapForward: forward message body is missing a "next" field');
  }

  const attachments = message.attachments;
  if (!Array.isArray(attachments) || attachments.length === 0) {
    throw new Error('unwrapForward: forward message has no attachments');
  }

  const attachedMessage = attachments[0]?.data?.json;
  if (attachedMessage === undefined || attachedMessage === null || typeof attachedMessage !== 'object') {
    throw new Error('unwrapForward: forward message attachment has no JSON-encoded message');
  }

  return { next, attachedMessage: attachedMessage as EncryptedMessage };
}
