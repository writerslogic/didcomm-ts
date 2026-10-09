import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

/**
 * Content-types this transport recognizes for a DIDComm envelope body.
 */
export type DidCommContentType =
  | "application/didcomm-encrypted+json"
  | "application/didcomm-encrypted+cbor";

export type OnMessage = (
  envelopeBytes: Uint8Array,
  contentType: DidCommContentType,
) => void | Promise<void>;

export interface HttpHandlerOptions {
  /** Largest accepted envelope in bytes; larger bodies get 413. Default 10 MiB. */
  maxBodyBytes?: number;
}

const DEFAULT_MAX_BODY_BYTES = 10 * 1024 * 1024;

const SUPPORTED_CONTENT_TYPES: readonly DidCommContentType[] = [
  "application/didcomm-encrypted+json",
  "application/didcomm-encrypted+cbor",
];

function isSupportedContentType(value: string): value is DidCommContentType {
  return (SUPPORTED_CONTENT_TYPES as readonly string[]).includes(value);
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));
}

/** Rejects an oversized upload and drops the connection rather than reading the rest of it. */
function rejectTooLarge(req: IncomingMessage, res: ServerResponse): void {
  res.setHeader("connection", "close");
  res.once("finish", () => req.destroy());
  sendJson(res, 413, { error: "envelope too large" });
}

/**
 * A `node:http` request handler that accepts one DIDComm envelope per POST
 * and invokes `onMessage` with the raw body bytes and its content-type.
 * Responds 202 on success, 415 for an unsupported content-type, 400 for an
 * empty body, 413 above `maxBodyBytes`, and 500 if `onMessage` throws.
 * Usable directly with `http.createServer` or mounted in any framework that
 * passes through Node's request/response objects with an unread body.
 */
export function createHttpHandler(
  onMessage: OnMessage,
  options: HttpHandlerOptions = {},
): (req: IncomingMessage, res: ServerResponse) => void {
  const maxBodyBytes = options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  return (req, res) => {
    if (req.method !== "POST") {
      res.setHeader("allow", "POST");
      sendJson(res, 405, { error: "method not allowed" });
      return;
    }
    const contentType = (req.headers["content-type"] ?? "").split(";")[0].trim();
    if (!isSupportedContentType(contentType)) {
      sendJson(res, 415, { error: "unsupported content-type" });
      return;
    }
    if (Number(req.headers["content-length"] ?? 0) > maxBodyBytes) {
      rejectTooLarge(req, res);
      return;
    }

    const chunks: Buffer[] = [];
    let received = 0;
    let rejected = false;
    req.on("data", (chunk: Buffer) => {
      if (rejected) return;
      received += chunk.length;
      if (received > maxBodyBytes) {
        rejected = true;
        rejectTooLarge(req, res);
        return;
      }
      chunks.push(chunk);
    });
    req.on("error", () => {
      rejected = true;
      if (!res.headersSent) sendJson(res, 400, { error: "request aborted" });
    });
    req.on("end", () => {
      if (rejected) return;
      if (received === 0) {
        sendJson(res, 400, { error: "empty body" });
        return;
      }
      void Promise.resolve()
        .then(() => onMessage(new Uint8Array(Buffer.concat(chunks)), contentType))
        .then(() => {
          res.writeHead(202).end();
        })
        .catch((err: unknown) => {
          sendJson(res, 500, { error: err instanceof Error ? err.message : String(err) });
        });
    });
  };
}

/**
 * Starts an HTTP receiver on `port` (0 for an ephemeral port) accepting
 * envelopes on `POST /`. Resolves once the server is listening.
 */
export function listenHttp(
  port: number,
  onMessage: OnMessage,
  options: HttpHandlerOptions = {},
): Promise<{ server: Server; port: number; close: () => Promise<void> }> {
  const handler = createHttpHandler(onMessage, options);
  const server = createServer((req, res) => {
    if ((req.url ?? "/").split("?")[0] !== "/") {
      sendJson(res, 404, { error: "not found" });
      return;
    }
    handler(req, res);
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, () => {
      const address = server.address();
      const boundPort = typeof address === "object" && address !== null ? address.port : port;
      resolve({
        server,
        port: boundPort,
        close: () =>
          new Promise<void>((res, rej) => {
            server.close((err) => (err ? rej(err) : res()));
          }),
      });
    });
  });
}

/**
 * Sends a DIDComm envelope to `url` via HTTP POST with the given
 * content-type header.
 */
export async function sendHttp(
  url: string,
  envelopeBytes: Uint8Array,
  contentType: DidCommContentType,
): Promise<globalThis.Response> {
  return fetch(url, {
    method: "POST",
    headers: { "content-type": contentType },
    body: Buffer.from(envelopeBytes),
  });
}
